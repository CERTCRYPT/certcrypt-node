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

//! Upstream client: submits submission sets to the issuance service.
//!
//! Wraps `POST /v1/submit`. The node is the issuer-side component that
//! talks to CERTCRYPT infrastructure; this is the one network call that path
//! makes (per the node README: "retry and idempotency around submission").
//! An accepted member returns `accepted`: the issuance service finalizes it
//! asynchronously.
//!
//! Under `submission-set/1` the issuance service evaluates each member
//! independently and returns a PER-MEMBER outcome (`SubmissionSetResponse`): a
//! member that fails does NOT tumble the valid ones (no all-or-nothing). The
//! node does NOT pre-verify the chain — the service re-verifies every member
//! regardless of what the node claims (verify, don't trust), so a second
//! verification in the node would add no guarantee. The submit IS the
//! verification; this client just carries the per-member result back.
//!
//! Two response shapes exist and both MUST be handled:
//!   - `SubmissionSetResponse` — the per-member path (the issuance service reached member
//!     evaluation; some accepted, some rejected, in any mix);
//!   - the flat `SubmitOutcome` — a pre-evaluation rejection that applies
//!     to the whole request before any member was evaluated (idempotency
//!     conflict, operator-recognition failure, unparseable submission set).

use capacity_artifacts::operator_recognition::OperatorRecognitionCredentialV1;
use capacity_artifacts::{SubmissionSetV1, SUBMISSION_SET_VERSION};
use serde::{Deserialize, Serialize};

/// The `POST /v1/submit` wire shape: the request envelope. `submission_set.schema` carries the canonical
/// artifact family label, `"submission-set/1"` — the same value the inner
/// payload declares, per the API contract's `schema` property.
#[derive(Debug, Clone, Serialize)]
struct SubmitSubmissionSetRequest {
    request_id: String,
    submission_set: SubmissionSetArtifact,
    /// Operator recognition is mandatory: the issuance service rejects a submit
    /// without a valid credential + possession proof for THIS submit.
    operator_recognition: OperatorRecognitionProof,
    /// CERTCRYPT-domain operational envelope (the issuer-elected close tier). Carries
    /// the issuer's settlement-window preference. Omitted (skipped) when the
    /// issuer sent none → the service resolves the catalog default. NOT part of the
    /// submission_set / proof / verifier semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<SubmitOperation>,
}

/// The `POST /v1/submit` wire shape: the operational envelope wrapping the
/// settlement preference. Kept minimal: the service rejects unknown fields.
#[derive(Debug, Clone, Serialize)]
struct SubmitOperation {
    settlement_preferences: SubmitSettlementPreferences,
}

/// The `POST /v1/submit` wire shape: settlement preferences (window profile +
/// fallback).
#[derive(Debug, Clone, Serialize)]
struct SubmitSettlementPreferences {
    window_profile: String,
    fallback_policy: String,
}

#[derive(Debug, Clone, Serialize)]
struct SubmissionSetArtifact {
    schema: String,
    payload: serde_json::Value,
}

/// The recognition proof attached to every submit (the `POST /v1/submit` wire
/// shape): the system-domain-signed credential plus a
/// base64 ML-DSA signature by the operator key over `request_id.submission_set_id`.
#[derive(Debug, Clone, Serialize)]
pub struct OperatorRecognitionProof {
    pub credential: OperatorRecognitionCredentialV1,
    pub possession_b64: String,
}

#[derive(Debug, Clone, Serialize)]
struct OpenNodeLinkRequest {
    operator_public_key_b64: String,
    nonce_b64: String,
    possession_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenNodeLinkResponse {
    pub link_request_id: String,
    pub user_code: String,
    pub claim_token: String,
    pub verification_uri: String,
    pub expires_in_seconds: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
struct ClaimNodeLinkRequest {
    claim_token: String,
    possession_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClaimNodeLinkResponse {
    pub status: String,
    pub operator_id: Option<String>,
    pub credential: Option<OperatorRecognitionCredentialV1>,
}

/// The per-member outcome shape of the `POST /v1/submit` response, at the
/// fields the node acts on. Field names and serde tags MUST match the wire
/// byte-for-byte, or the node misreads it.
#[derive(Debug, Clone, Deserialize)]
pub struct SubmissionSetResponse {
    /// Deterministic identity of the transported set (idempotency + operator
    /// participation anchor). NEVER what a proof/settlement anchors.
    pub submission_set_id: String,
    /// One outcome per submitted member, in submission order.
    pub results: Vec<MemberOutcome>,
}

/// One member's outcome. `status` is flattened in.
#[derive(Debug, Clone, Deserialize)]
pub struct MemberOutcome {
    /// Position of the member in the submitted set — the stable key the node
    /// maps back to what it sent.
    pub commitment_index: usize,
    #[serde(flatten)]
    pub status: MemberStatus,
}

/// Per-member status, discriminated by `status` in
/// snake_case. `Unknown` fails closed on any future/unrecognized variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MemberStatus {
    /// Member accepted into a fixation path; carries its operation id.
    Accepted { operation_id: String },
    /// Member failed per-member validation with an actionable reason.
    Rejected {
        reason_code: String,
        message: String,
    },
    /// Member's commitment was already consumed or already claimed.
    ReplayDetected { message: String },
    /// Any future/unknown member status — fail closed rather than misinterpret.
    #[serde(other)]
    Unknown,
}

pub use crate::store::CapacityShortfall;

/// The flat outcome: a verdict on the set as a whole, returned when no member
/// was evaluated on its own — a set precondition failed (idempotency conflict,
/// operator-recognition failure, unparseable submission set, …) or the set as a
/// whole does not fit the available capacity. It has no per-member results
/// because no member was reached.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FlatOutcome {
    Rejected {
        operation_id: Option<String>,
        reason_code: String,
        message: String,
    },
    /// The set does not fit: `required` is what it costs, `available` what the
    /// contract can cover, `missing` the difference.
    InsufficientCapacity {
        #[serde(default)]
        capacity: Option<CapacityShortfall>,
    },
    /// Any other flat status — fail closed.
    #[serde(other)]
    Unknown,
}

/// What the node gets back from a submit. The service returns one of two shapes; we
/// try the per-member shape first (the normal path under submission-set/1) and
/// fall back to the flat pre-evaluation rejection.
#[derive(Debug, Clone)]
pub enum SubmitResponse {
    /// The service reached member evaluation: per-member outcomes (any mix).
    PerMember(SubmissionSetResponse),
    /// The request was rejected as a whole before member evaluation.
    Flat(FlatOutcome),
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("serializing submission-set payload failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("HTTP request to the issuance service failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("the issuance service returned HTTP {status}: {body}")]
    Status {
        status: u16,
        body: String,
        /// The service's `Retry-After`, in seconds form only. `None` when absent
        /// or given as an HTTP date (the service never sends one).
        retry_after: Option<std::time::Duration>,
    },
}

impl UpstreamError {
    async fn from_response(resp: reqwest::Response) -> Self {
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(crate::relay::parse_retry_after);
        let body = resp.text().await.unwrap_or_default();
        UpstreamError::Status {
            status,
            body,
            retry_after,
        }
    }

    /// The wait the service asked for, if it asked for one. Present on planned
    /// maintenance (`503`) and on rate limiting (`429`): both say "come back
    /// later", and spending a delivery attempt on them would turn a planned
    /// pause into a dead-letter.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            // Honored on 503 and 429 only: on any other
            // status the header does not turn a failure into a requested pause.
            UpstreamError::Status {
                status: 503 | 429,
                retry_after,
                ..
            } => *retry_after,
            _ => None,
        }
    }

    /// This failure as the transport-retry policy sees it.
    pub fn as_outcome(&self) -> crate::relay::TransportOutcome {
        match self {
            UpstreamError::Http(_) => crate::relay::TransportOutcome::Transport,
            UpstreamError::Status {
                status,
                retry_after,
                ..
            } => crate::relay::TransportOutcome::Http {
                status: *status,
                retry_after: *retry_after,
            },
            // Not a transport failure at all: the request could not be built.
            UpstreamError::Serialize(_) => crate::relay::TransportOutcome::Http {
                status: 400,
                retry_after: None,
            },
        }
    }

    /// The status of a DEFINITIVE refusal, if this is one: an HTTP answer that
    /// is neither a success nor transient (408, 425, 429 and every 5xx are
    /// transient). In practice the 4xx family — 400, 401, 403, 404, 409, 413,
    /// 422 and the rest.
    ///
    /// The service read the request and said no. Sending the same bytes again
    /// cannot change that answer, so a refused submission is neither accepted
    /// for retry nor kept in the outbox: the issuer is told at once, and a
    /// refusal met during background delivery is dead-lettered on the spot.
    /// This is the same line the transport-retry policy draws (`decide`
    /// returns rather than retrying), so the two can never disagree.
    pub fn refusal_status(&self) -> Option<u16> {
        match self {
            UpstreamError::Status { status, .. }
                if !(matches!(*status, 408 | 425 | 429) || (500..=599).contains(status)) =>
            {
                Some(*status)
            }
            _ => None,
        }
    }

    /// Whether the failure says the service is UNAVAILABLE — unreachable,
    /// overloaded, timed out, in maintenance, or behind a gateway that could
    /// not reach it — and nothing about the submission itself. Such a failure
    /// is retried for as long as it lasts: it never dead-letters, because the
    /// set is fine and only the path to the service is not.
    ///
    /// A `500` is not that. It says the service FAILED on this request, which
    /// may be the request: a deterministic fault answers the same way every
    /// time, and retrying it forever would hide it. It is retried a bounded
    /// number of times and then dead-lettered, where it is visible and can be
    /// redriven once the cause is fixed. (A 4xx is not retried at all: see
    /// [`Self::refusal_status`].)
    pub fn is_transient(&self) -> bool {
        match self {
            UpstreamError::Http(_) => true,
            UpstreamError::Status { status, .. } => {
                matches!(*status, 408 | 425 | 429 | 502 | 503 | 504)
            }
            UpstreamError::Serialize(_) => false,
        }
    }
}

/// Client for the issuance service's submission surface.
#[derive(Debug, Clone)]
pub struct UpstreamClient {
    base_url: String,
    http: reqwest::Client,
    request_timeout: std::time::Duration,
}

impl UpstreamClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        // Explicit timeouts: a hung/unreachable issuance service MUST NOT block the node
        // indefinitely (default reqwest has NO timeout). Overridable by env:
        //   CERTCRYPT_API_TIMEOUT_SECS         (total request, default 10)
        //   CERTCRYPT_API_CONNECT_TIMEOUT_SECS (connect phase, default 3)
        // A timed-out submit surfaces as a retryable transport error; the SDK
        // and the node's outbox relay retry with the SAME request_id,
        // which the issuance service deduplicates idempotently.
        let total = std::env::var("CERTCRYPT_API_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(10);
        let connect = std::env::var("CERTCRYPT_API_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(3);
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(total))
            .connect_timeout(std::time::Duration::from_secs(connect))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            request_timeout: std::time::Duration::from_secs(total),
        }
    }

    /// The total budget of one upstream request. An inline submit cannot still be
    /// in flight once this has elapsed, which is what the outbox's grace period
    /// is sized from.
    pub fn request_timeout(&self) -> std::time::Duration {
        self.request_timeout
    }

    pub async fn open_node_link(
        &self,
        operator_public_key_b64: &str,
        nonce_b64: &str,
        possession_b64: &str,
    ) -> Result<OpenNodeLinkResponse, UpstreamError> {
        let resp = self
            .http
            .post(format!("{}/v1/node-links", self.base_url))
            .json(&OpenNodeLinkRequest {
                operator_public_key_b64: operator_public_key_b64.to_string(),
                nonce_b64: nonce_b64.to_string(),
                possession_b64: possession_b64.to_string(),
            })
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(UpstreamError::from_response(resp).await);
        }
        Ok(resp.json().await?)
    }

    pub async fn claim_node_link(
        &self,
        link_request_id: &str,
        claim_token: &str,
        possession_b64: &str,
    ) -> Result<(u16, ClaimNodeLinkResponse), UpstreamError> {
        let resp = self
            .http
            .post(format!(
                "{}/v1/node-links/{}/claim",
                self.base_url, link_request_id
            ))
            .json(&ClaimNodeLinkRequest {
                claim_token: claim_token.to_string(),
                possession_b64: possession_b64.to_string(),
            })
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status != 200 && status != 202 {
            return Err(UpstreamError::from_response(resp).await);
        }
        Ok((status, resp.json().await?))
    }

    /// Submit a closed submission set. `request_id` is the idempotency key (a
    /// 26-char ULID); resubmitting the same `request_id` is safe and returns the
    /// same outcome on the issuance service side. `recognition` is the MANDATORY
    /// operator recognition proof: the issuance service rejects a submit without
    /// a valid credential + a possession proof over `request_id.submission_set_id`.
    /// `settlement_preferences` (window_profile, fallback_policy) is the issuer's
    /// close-tier election, forwarded to the issuance service as `operation.settlement_
    /// preferences`. `None` → the issuance service resolves the catalog default.
    pub async fn submit_submission_set(
        &self,
        request_id: &str,
        submission_set: &SubmissionSetV1,
        recognition: OperatorRecognitionProof,
        settlement_preferences: Option<(String, String)>,
    ) -> Result<SubmitResponse, UpstreamError> {
        let payload = serde_json::to_value(submission_set)?;
        let body = SubmitSubmissionSetRequest {
            request_id: request_id.to_string(),
            submission_set: SubmissionSetArtifact {
                // THE CANONICAL FAMILY LABEL, from the constant — not a
                // separate "wire tag". The envelope does not carry a different
                // label from the artifact inside it: per the API contract,
                // `schema` is the "Canonical artifact family label for the
                // submitted set object", and the only value it gives is
                // `submission-set/1`. Sending anything else records a label
                // the artifact validator would reject.
                schema: SUBMISSION_SET_VERSION.to_string(),
                payload,
            },
            operator_recognition: recognition,
            operation: settlement_preferences.map(|(window_profile, fallback_policy)| {
                SubmitOperation {
                    settlement_preferences: SubmitSettlementPreferences {
                        window_profile,
                        fallback_policy,
                    },
                }
            }),
        };

        let resp = self
            .http
            .post(format!("{}/v1/submit", self.base_url))
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(UpstreamError::from_response(resp).await);
        }
        // The issuance service returns one of two shapes on success (HTTP 200). The
        // per-member shape carries `results`; the flat pre-evaluation rejection
        // carries a top-level `status`. Branch on the presence of `results`.
        let body: serde_json::Value = resp.json().await?;
        if body.get("results").is_some() {
            Ok(SubmitResponse::PerMember(serde_json::from_value(body)?))
        } else {
            Ok(SubmitResponse::Flat(serde_json::from_value(body)?))
        }
    }

    /// Register an operator.domain-binding/1 statement
    /// (`POST /v1/operator-domain-bindings`). The outcome is the body's
    /// `status`; an HTTP error is returned as [`UpstreamError::Status`].
    pub async fn register_domain_binding(
        &self,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        let resp = self
            .http
            .post(format!("{}/v1/operator-domain-bindings", self.base_url))
            .json(body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(UpstreamError::from_response(resp).await);
        }
        Ok(resp.json().await?)
    }

    /// Forward an issuer activation (OTP) to the issuance service's `POST /v1/activate` and
    /// return its JSON body verbatim. Pure pass-through: the node does not parse
    /// or persist the Level-1 binding — it only transports the request upstream
    /// (the SDK talks only to the node) and relays the issuance service's response. The
    /// activation code + holder_key_set_root the issuer presents ride in `body`.
    pub async fn activate(
        &self,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        let resp = self
            .http
            .post(format!("{}/v1/activate", self.base_url))
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(UpstreamError::from_response(resp).await);
        }
        Ok(resp.json().await?)
    }

    /// Fetch the current, authoritative state of ONE operation from the issuance service by its
    /// upstream operation id. The node's journal only records the submit-time
    /// outcome (`Accepted`); the terminal `independent_ready` transition + the PoI
    /// and settlement material are owned by the issuance service and finalized
    /// ASYNCHRONOUSLY. This is the read path the node uses to RECONCILE a
    /// non-terminal local record with the issuance service so the issuer (who only talks to the
    /// node) can observe the terminal state.
    ///
    /// This is a live pass-through, NOT custody: the returned body (status, and
    /// when terminal the `independence_proof` + `settlement_material`) is forwarded
    /// to the issuer and never persisted in the node (the node stays a
    /// non-custodian — it holds operational state, never the certified material).
    ///
    /// Returns the raw JSON body. `None` if the issuance service returns 404 (the op is not
    /// visible upstream yet), so the caller can fall back to the local record.
    pub async fn get_operation(
        &self,
        operation_id: &str,
        issuer_read_proof: Option<&str>,
        operator_read_proof: Option<&str>,
    ) -> Result<Option<serde_json::Value>, UpstreamError> {
        let path = format!("/v1/operations/{operation_id}");
        self.chained_read(&path, issuer_read_proof, operator_read_proof)
            .await
    }

    /// Read one emission by the digest of the capacity evidence that produced it.
    ///
    /// The lookup that survives THIS node. The attempt id belongs to the issuance service and
    /// the operation id to this journal, but the digest belongs to the ISSUER: it
    /// recomputes it from evidence it signed itself. An issuer whose node was
    /// restarted with an in-memory journal, or who moved to another node, can
    /// still ask about an emission the issuance service still holds.
    pub async fn get_emission_by_commitment(
        &self,
        independence_ref: &str,
        issuer_read_proof: Option<&str>,
        operator_read_proof: Option<&str>,
    ) -> Result<Option<serde_json::Value>, UpstreamError> {
        let path = format!("/v1/emissions/by-commitment/{independence_ref}");
        self.chained_read(&path, issuer_read_proof, operator_read_proof)
            .await
    }

    /// A GET under the chained-read contract.
    ///
    /// BOTH halves of the read chain travel upstream. The issuer's is relayed
    /// VERBATIM — the node cannot mint it (it holds no leaf of that key set) and
    /// must not alter it, since it is what tells the issuance service whose data
    /// this is. The node's own half proves the request came through a recognized
    /// operator. The service requires the pair; neither substitutes for the other.
    async fn chained_read(
        &self,
        path: &str,
        issuer_read_proof: Option<&str>,
        operator_read_proof: Option<&str>,
    ) -> Result<Option<serde_json::Value>, UpstreamError> {
        let mut req = self.http.get(format!("{}{path}", self.base_url));
        if let Some(p) = issuer_read_proof {
            req = req.header("x-certcrypt-issuer-read", p);
        }
        if let Some(p) = operator_read_proof {
            req = req.header("x-certcrypt-operator-read", p);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(UpstreamError::from_response(resp).await);
        }
        Ok(Some(resp.json().await?))
    }

    /// Ask the issuance service which emissions this issuer has in flight — the entry point
    /// for a reconciler that lost its handles.
    ///
    /// Same relay shape as `get_operation`, with one difference that matters: the
    /// resource both halves sign is the QUERY (`emissions:unresolved:<since>`),
    /// not an operation id. It has to be — a caller that lost its handles has no
    /// id to name, which is the whole reason this path exists.
    ///
    /// `since` is forwarded BYTE FOR BYTE as the issuer wrote it, never
    /// reformatted. The issuer signed that exact string; normalizing an offset
    /// (`+02:00` → `Z`) here would leave the two halves covering different
    /// messages and the issuance service would reject one — the silent failure documented on
    /// the operation path, which surfaces as an issuer polling forever.
    ///
    /// The node cannot mint the issuer's half and does not try: without it the issuance service
    /// refuses before doing any work on the node's behalf. The node's own half
    /// only ever asserts "and it came through me".
    ///
    /// Live pass-through, NOT custody: the body is forwarded to the issuer and
    /// never persisted here.
    pub async fn list_unresolved_emissions(
        &self,
        since_raw: &str,
        limit: Option<u32>,
        issuer_read_proof: Option<&str>,
        operator_read_proof: Option<&str>,
    ) -> Result<serde_json::Value, UpstreamError> {
        let mut req = self
            .http
            .get(format!("{}/v1/emissions/unresolved", self.base_url))
            .query(&[("since", since_raw)]);
        if let Some(n) = limit {
            req = req.query(&[("limit", n.to_string())]);
        }
        if let Some(p) = issuer_read_proof {
            req = req.header("x-certcrypt-issuer-read", p);
        }
        if let Some(p) = operator_read_proof {
            req = req.header("x-certcrypt-operator-read", p);
        }
        let resp = req.send().await?;
        let status = resp.status();
        // No 404-to-None here, unlike get_operation: a 404 means the proven root
        // resolves to no active integration (revoked, or never bound), which is a
        // real answer the issuer must see — not a local record to fall back on.
        if !status.is_success() {
            return Err(UpstreamError::from_response(resp).await);
        }
        Ok(resp.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_member_response_deserializes_each_status() {
        let resp: SubmissionSetResponse = serde_json::from_value(serde_json::json!({
            "submission_set_id": "abc123",
            "results": [
                {"commitment_index": 0, "status": "accepted", "operation_id": "OP1"},
                {"commitment_index": 1, "status": "rejected", "reason_code": "submission_set_invalid", "message": "x"},
                {"commitment_index": 2, "status": "replay_detected", "message": "already consumed"},
                {"commitment_index": 3, "status": "some_future_status"}
            ]
        }))
        .unwrap();
        assert_eq!(resp.submission_set_id, "abc123");
        assert_eq!(resp.results.len(), 4);
        assert!(matches!(
            resp.results[0].status,
            MemberStatus::Accepted { .. }
        ));
        assert!(matches!(
            resp.results[1].status,
            MemberStatus::Rejected { .. }
        ));
        assert!(matches!(
            resp.results[2].status,
            MemberStatus::ReplayDetected { .. }
        ));
        assert!(matches!(resp.results[3].status, MemberStatus::Unknown));
    }

    fn status(status: u16) -> UpstreamError {
        UpstreamError::Status {
            status,
            body: String::new(),
            retry_after: None,
        }
    }

    #[test]
    fn definitive_refusals_are_the_non_transient_4xx() {
        for s in [400u16, 401, 403, 404, 409, 410, 413, 422] {
            assert_eq!(status(s).refusal_status(), Some(s), "{s} is a refusal");
        }
        for s in [408u16, 425, 429, 500, 502, 503, 504] {
            assert_eq!(status(s).refusal_status(), None, "{s} is not a refusal");
        }
    }

    #[test]
    fn a_refusal_is_exactly_what_the_retry_policy_returns_on() {
        // The inline path and the relay must draw the same line: whatever the
        // transport-retry policy does not retry is a refusal, and nothing else.
        let policy = crate::relay::RetryPolicy {
            max_elapsed: None,
            max_attempts: None,
            backoff_base: std::time::Duration::from_millis(200),
            backoff_cap: std::time::Duration::from_secs(300),
        };
        for s in 400u16..=599 {
            let e = status(s);
            let returns = matches!(
                crate::relay::decide(&policy, e.as_outcome(), 0, 0),
                crate::relay::Decision::Return
            );
            assert_eq!(e.refusal_status().is_some(), returns, "status {s}");
        }
    }

    #[test]
    fn flat_pre_evaluation_rejection_deserializes() {
        let flat: FlatOutcome = serde_json::from_value(serde_json::json!({
            "status":"rejected","operation_id":"OP2","reason_code":"idempotency_conflict","message":"x"
        }))
        .unwrap();
        assert!(matches!(flat, FlatOutcome::Rejected { .. }));

        // The capacity verdict is one answer for the set, with its figures.
        let short: FlatOutcome = serde_json::from_value(serde_json::json!({
            "status": "insufficient_capacity",
            "operation_id": "00000000000000000000000000",
            "capacity": {"required": "5.00", "available": "2.00", "missing": "3.00"}
        }))
        .unwrap();
        let FlatOutcome::InsufficientCapacity { capacity: Some(c) } = short else {
            panic!("expected insufficient_capacity with figures");
        };
        assert_eq!(c.missing, "3.00");

        let unknown: FlatOutcome =
            serde_json::from_value(serde_json::json!({"status":"some_future_status"})).unwrap();
        assert!(matches!(unknown, FlatOutcome::Unknown));
    }
}
