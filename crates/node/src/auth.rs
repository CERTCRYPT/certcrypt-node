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

//! Issuer authentication at the node edge — SELF-VERIFYING, OFFLINE.
//!
//! Zero-trust (verify, don't trust): the node does NOT hold a list of issuer
//! tokens and does NOT call the issuance service to validate. The issuer PRESENTS a
//! proof and the node VERIFIES it locally with only the system-domain's public
//! key — exactly as the offline verifier checks a PoI. This mirrors, in the
//! issuer→node direction, the `operator.recognition/1` proof the node presents
//! to the issuance service.
//!
//! The proof (`X-Certcrypt-Issuer-Auth` header, base64 JSON) carries:
//!   - `signed_level1`: the system-domain-signed Level-1 binding over the issuer's
//!     `holder_key_set_root` (composite P-256 + ML-DSA-65).
//!   - `disclosure`: a leaf public key + Merkle inclusion proof to that root.
//!   - `challenge` + `possession_b64`: a fresh ML-DSA-65 signature by that leaf
//!     over the per-request challenge BOUND TO THE REQUEST (possession +
//!     anti-replay): the leaf signs [`RequestBinding::message`] —
//!     `certcrypt:issuer-auth:1|<challenge>|<host>|<METHOD> <path?query>|<sha3-256
//!     of the body>` — which the node rebuilds from the request it received.
//!
//! Six checks, fail-closed:
//!   1. validity window of the binding;
//!   2. fingerprint binding == the node's pinned system_root_fingerprint;
//!   3. binding composite signature verifies against the resolved Level-1 key;
//!   4. the disclosed leaf is a member of `holder_key_set_root`;
//!   5. the possession signature verifies for that leaf over the challenge and
//!      THIS request (host, method, path and query, body);
//!   6. the challenge is FRESH and has not been seen before.
//!
//! Check 6 is what makes checks 1-5 mean anything for a request. Without it the
//! possession signature proves only that the issuer signed *some* challenge *at
//! some point* — and since the issuer hands the whole proof to the node, the node
//! could keep it and replay it forever, speaking as that issuer without the issuer
//! ever initiating anything. Emission would not be exposed (a submit also needs a
//! `capacity_evidence` signed per certificate, which cannot be forged from a
//! stored proof), but every READ would be: the operation history and the
//! dead-letter queue of an issuer, readable indefinitely by whoever transported
//! one request.
//! For a zero-data system that is a disclosure hole, and it is the reason this
//! check exists.
//!
//! The authenticated SCOPE is the `holder_key_set_root` (the binding authorizes a
//! holder, not a contract). It is derived from the credential, never declared by
//! the caller.

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use capacity_artifacts::capacity_evidence::OperationKeyDisclosure;
use capacity_artifacts::capacity_holder_authorization::Level1AuthorizationBinding;
use capacity_artifacts::composite_sig::CompositeSignatureWire;
use capacity_verify::manifest::ManifestResolver;
use serde::Deserialize;
use sha3::{Digest, Sha3_256};

/// How far a challenge's timestamp may sit from the node's clock, in seconds. A
/// proof older than this is refused however well it verifies.
///
/// 120s in both directions: generous enough for clock skew between an issuer's
/// machine and the node plus normal latency, short enough that a captured proof
/// is worthless within minutes. It bounds the replay window; the seen-cache below
/// closes it entirely for the window's duration.
const CHALLENGE_MAX_SKEW_SECS: i64 = 120;

/// Upper bound on remembered challenges. Entries expire by age
/// (`CHALLENGE_MAX_SKEW_SECS`), so this is a memory ceiling for a burst, not a
/// retention policy — at any sane request rate the map holds far fewer.
const CHALLENGE_CACHE_MAX: usize = 100_000;

/// Remembers recently accepted challenges so none is accepted twice.
///
/// Deliberately in-process and non-durable. A restart forgets, but every forgotten
/// challenge is also outside its freshness window within
/// `CHALLENGE_MAX_SKEW_SECS`, so the two guards overlap and nothing is left
/// unprotected. Making this durable or shared would buy nothing and would put a
/// datastore in the authentication path of every request.
#[derive(Default)]
pub struct ChallengeCache {
    seen: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

impl ChallengeCache {
    /// Record a challenge as used. `false` if it was already present — a replay.
    ///
    /// Prunes expired entries on insert: the sweep is O(n) but only runs when the
    /// map is at its ceiling, and every entry it walks is one that could not be
    /// accepted anyway.
    fn accept(&self, challenge: &str, now_unix: i64) -> bool {
        let mut seen = match self.seen.lock() {
            Ok(g) => g,
            // A panic elsewhere poisoned the lock. Fail CLOSED: refuse the proof
            // rather than authenticate without replay protection.
            Err(_) => return false,
        };
        if seen.contains_key(challenge) {
            return false;
        }
        if seen.len() >= CHALLENGE_CACHE_MAX {
            seen.retain(|_, ts| now_unix - *ts <= CHALLENGE_MAX_SKEW_SECS);
            // Still full of live entries: refuse rather than grow without bound.
            // Fail-closed under flood, never "accept because we cannot remember".
            if seen.len() >= CHALLENGE_CACHE_MAX {
                return false;
            }
        }
        seen.insert(challenge.to_string(), now_unix);
        true
    }
}

/// The node's trust anchor for verifying issuer proofs offline. There is no
/// list of issuer tokens to trust: the node holds the material to VERIFY a
/// proof — the manifest resolver (fingerprint + kid
/// → system-domain Level-1 public key) and the pinned `system_root_fingerprint`.
#[derive(Clone)]
pub struct IssuerVerifier {
    pub resolver: Arc<dyn ManifestResolver>,
    pub system_root_fingerprint: Arc<String>,
    /// Shared across handlers so a challenge accepted on one route cannot be
    /// replayed on another.
    pub challenges: Arc<ChallengeCache>,
}

/// The Level-1 binding + its composite signature, as the SDK sends it. The wire
/// is snake_case, exactly the field names below: `level1_binding` /
/// `level1_signature`, inside the proof's `signed_level1`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedLevel1Binding {
    pub level1_binding: Level1AuthorizationBinding,
    pub level1_signature: CompositeSignatureWire,
}

/// The proof the issuer presents in the `X-Certcrypt-Issuer-Auth` header
/// (base64(JSON)). `challenge` is the message the possession signature covers —
/// it binds the proof to this request (anti-replay), exactly as
/// `operator.recognition` binds `request_id.submission_set_id`.
#[derive(Debug, Clone, Deserialize)]
pub struct IssuerAuthProof {
    pub signed_level1: SignedLevel1Binding,
    pub disclosure: OperationKeyDisclosure,
    pub challenge: String,
    pub possession_b64: String,
}

/// The authenticated issuer scope, extracted and cryptographically verified from
/// the presented proof. Handlers receive this instead of trusting a body field.
/// The scope is the `holder_key_set_root` the system-domain authorized.
#[derive(Debug, Clone)]
pub struct AuthedIssuer {
    /// The authorized holder key set root — the node's partition/scope key.
    pub holder_key_set_root: String,
}

const HEADER: &str = "x-certcrypt-issuer-auth";

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthedIssuer
where
    IssuerVerifier: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let verifier = IssuerVerifier::from_ref(state);

        // Parse the proof from the header: base64(JSON).
        let raw = parts
            .headers
            .get(HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "missing issuer auth proof"))?;
        let json = B64
            .decode(raw.trim().as_bytes())
            .map_err(|_| (StatusCode::UNAUTHORIZED, "issuer auth proof not base64"))?;
        let proof: IssuerAuthProof = serde_json::from_slice(&json)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "issuer auth proof malformed"))?;

        // Put there by the router's middleware for every request; its absence
        // is a wiring error, refused rather than verified against nothing.
        let request = parts
            .extensions
            .get::<RequestBinding>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "issuer auth proof not verifiable"))?;
        verify_issuer_proof(&verifier, &proof, &request)
            .map(|holder_key_set_root| AuthedIssuer {
                holder_key_set_root,
            })
            .map_err(|e| {
                // The reason is logged, never returned: an unauthenticated caller
                // learning WHICH check failed is told how to probe the next one.
                // Operators debugging a misconfiguration have the log; a prober
                // gets the same opaque 401 either way.
                tracing::warn!(reason = %e, "issuer auth proof rejected");
                (
                    StatusCode::UNAUTHORIZED,
                    "issuer auth proof does not verify",
                )
            })
    }
}

/// Signing domain of the issuer's per-request proof.
pub const ISSUER_AUTH_DOMAIN: &str = "certcrypt:issuer-auth:1";

/// The request an issuer proof must have been made for, as the node received
/// it. Built by the router's middleware (which reads the body to hash it) and
/// read by the [`AuthedIssuer`] extractor.
///
/// Binding the proof to the request is what makes a captured proof worthless
/// for anything but repeating that very request: not another route, not another
/// body, not another node. And repeating it is harmless — a submit with the
/// same `request_id` is answered from what the node already holds, a read reads
/// again. So the single-use cache below needs no shared store between replicas
/// or across restarts: a proof that slips past one process's cache can only
/// re-ask what was already asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBinding {
    /// The `Host` header as received (`node.example:443` stays as sent).
    pub host: String,
    pub method: String,
    /// Path plus query, exactly as received (`/v1/operations/op_1?x=1`).
    pub path_and_query: String,
    /// Lowercase hex SHA3-256 of the request body (of the empty string for none).
    pub body_sha3_hex: String,
}

impl RequestBinding {
    /// The bytes the issuer's leaf signs for `challenge` on this request.
    pub fn message(&self, challenge: &str) -> String {
        format!(
            "{ISSUER_AUTH_DOMAIN}|{challenge}|{}|{} {}|{}",
            self.host, self.method, self.path_and_query, self.body_sha3_hex
        )
    }
}

/// Verify the issuer proof OFFLINE and return the authorized `holder_key_set_root`.
/// Fail-closed at every step. No DB, no issuance-service call — only the pinned fingerprint and
/// the resolved system-domain Level-1 public key.
pub fn verify_issuer_proof(
    verifier: &IssuerVerifier,
    proof: &IssuerAuthProof,
    request: &RequestBinding,
) -> Result<String, String> {
    let binding = &proof.signed_level1.level1_binding;

    // 1. Validity window of the binding.
    let now = chrono::Utc::now();
    let valid_from = chrono::DateTime::parse_from_rfc3339(&binding.valid_from)
        .map_err(|e| format!("valid_from parse: {e}"))?
        .with_timezone(&chrono::Utc);
    let valid_until = chrono::DateTime::parse_from_rfc3339(&binding.valid_until)
        .map_err(|e| format!("valid_until parse: {e}"))?
        .with_timezone(&chrono::Utc);
    if now < valid_from || now > valid_until {
        return Err("binding outside its validity window".into());
    }

    // 2. Fingerprint binding (anti bait-and-switch): the binding must be issued
    //    under the fingerprint this node is pinned to.
    if binding.system_root_fingerprint.as_str() != verifier.system_root_fingerprint.as_str() {
        return Err("binding system_root_fingerprint is not the one this node trusts".into());
    }

    // 3. Binding composite signature against the resolved system-domain Level-1 key.
    if !verifier
        .resolver
        .fingerprint_is_known(&binding.system_root_fingerprint)
    {
        return Err("system_root_fingerprint unknown to this node".into());
    }
    let l1 = verifier
        .resolver
        .resolve(
            &binding.system_root_fingerprint,
            &binding.authorization_issuer_kid,
        )
        .map_err(|e| format!("authorization_issuer_kid unresolvable: {e}"))?;
    // The Level-1 entry must have been the active signing entry when the
    // binding says it was issued (`system-manifest/1` §7.5): a key rotated out
    // signs nothing valid after its interval, however well the signature checks.
    if !l1.active_at_rfc3339(&binding.valid_from) {
        return Err("binding starts outside the active interval of its Level-1 key".into());
    }
    let signing_bytes = binding
        .signing_bytes()
        .map_err(|e| format!("binding signing_bytes: {e}"))?;
    let binding_digest_hex = hex::encode(Sha3_256::digest(&signing_bytes));
    capacity_verify::composite::verify_composite(
        capacity_verify::composite::REQUIRED_PROFILE,
        &binding_digest_hex,
        &proof.signed_level1.level1_signature,
        capacity_verify::composite::CompositePublicKeys {
            classical_pub: &l1.classical_public_key,
            mldsa_pub: &l1.public_key,
        },
    )
    .map_err(|e| format!("binding composite signature: {e}"))?;

    // 4. Leaf membership: the disclosed leaf belongs to holder_key_set_root.
    if !proof
        .disclosure
        .verify_membership(&binding.holder_key_set_root)
    {
        return Err("disclosed leaf is not a member of holder_key_set_root".into());
    }

    // 5. Possession: the leaf signed the per-request challenge FOR THIS REQUEST.
    let leaf_pk = proof
        .disclosure
        .public_key()
        .ok_or_else(|| "disclosure public_key not base64".to_string())?;
    let possession_sig = B64
        .decode(proof.possession_b64.as_bytes())
        .map_err(|e| format!("possession_b64: {e}"))?;
    let message = request.message(&proof.challenge);
    capacity_verify::mldsa::verify_detached(&leaf_pk, &possession_sig, message.as_bytes())
        .map_err(|_| {
            "possession proof does not verify for this challenge and request".to_string()
        })?;

    // 6. Freshness + single use. Steps 1-5 prove the issuer signed THIS challenge;
    //    only this step proves the issuer signed it FOR THIS REQUEST. The issuer
    //    necessarily hands the entire proof to the node, so without this a node
    //    could store it and re-present it at will — see the module header.
    //
    //    Format is `<unix_millis>.<base64 random>`, minted per request by the SDK.
    //    The timestamp is not trusted as a fact, it is only checked for being
    //    close to now; the random suffix is what makes two challenges from the
    //    same millisecond distinct.
    let (ts_millis, _) = proof
        .challenge
        .split_once('.')
        .ok_or_else(|| "challenge is not <millis>.<random>".to_string())?;
    let ts_millis: i64 = ts_millis
        .parse()
        .map_err(|_| "challenge timestamp is not a number".to_string())?;
    let challenge_secs = ts_millis / 1000;
    let now_secs = now.timestamp();
    if (now_secs - challenge_secs).abs() > CHALLENGE_MAX_SKEW_SECS {
        return Err("challenge is outside the accepted freshness window".into());
    }
    // Checked LAST so a proof that fails any earlier step never consumes a cache
    // slot — otherwise an unauthenticated caller could fill it with garbage.
    if !verifier.challenges.accept(&proof.challenge, now_secs) {
        return Err("challenge already used".into());
    }

    Ok(binding.holder_key_set_root.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use capacity_artifacts::composite_sig::PROFILE_P256_MLDSA65;
    use capacity_verify::manifest::{ResolvedManifestEntry, StaticManifestResolver};

    /// Synthetic system-root fingerprint: the static resolver below is seeded
    /// under it, so any 64-hex value works and none names a real deployment.
    const FP: &str = "abababababababababababababababababababababababababababababababab";
    const KID: &str = "test-l1-kid";

    /// The request every proof built by `make` was made for.
    fn req() -> RequestBinding {
        RequestBinding {
            host: "node.test".into(),
            method: "POST".into(),
            path_and_query: "/v1/issue".into(),
            body_sha3_hex: hex::encode(Sha3_256::digest(b"{}")),
        }
    }

    /// The same vector is asserted by certcrypt-sdk-js and certcrypt-sdk-python:
    /// the node rebuilds, byte for byte, what the SDKs sign.
    #[test]
    fn the_message_matches_the_shared_vector() {
        let request = RequestBinding {
            host: "127.0.0.1:4041".into(),
            method: "POST".into(),
            path_and_query: "/v1/issue".into(),
            body_sha3_hex: hex::encode(Sha3_256::digest(b"{}")),
        };
        assert_eq!(
            request.message("1700000000000.abc"),
            "certcrypt:issuer-auth:1|1700000000000.abc|127.0.0.1:4041|POST /v1/issue|\
             840eb7aa2a9935de63366bacbe9d97e978a859e93dc792a0334de60ed52f8e99"
        );
    }

    /// A captured proof is good for its own request only: another route, body,
    /// method or node refuses it — so replaying it can only repeat that request.
    #[test]
    fn a_proof_is_bound_to_its_request() {
        let others = [
            RequestBinding {
                path_and_query: "/v1/outbox/dead".into(),
                ..req()
            },
            RequestBinding {
                body_sha3_hex: hex::encode(Sha3_256::digest(b"{\"x\":1}")),
                ..req()
            },
            RequestBinding {
                method: "GET".into(),
                ..req()
            },
            RequestBinding {
                host: "other-node.test".into(),
                ..req()
            },
        ];
        for other in others {
            let (v, p) = make(|_, _| {});
            let err = verify_issuer_proof(&v, &p, &other).expect_err("another request");
            assert!(err.contains("possession"), "{err}");
            // A refused proof does not spend its challenge: the right request passes.
            verify_issuer_proof(&v, &p, &req()).unwrap();
        }
    }

    /// Build a fully valid proof + a verifier seeded with the matching L1 key.
    /// The closure `mutate` may tamper the proof before it is returned, letting
    /// each test isolate one failed check. Returns (verifier, proof).
    fn make(
        mutate: impl FnOnce(&mut IssuerAuthProof, &str /*root*/),
    ) -> (IssuerVerifier, IssuerAuthProof) {
        // System-domain L1 keypair (ML-DSA seed + P-256 seed derived from it,
        // `composite-signature/1`).
        let l1_seed = [7u8; 32];
        let (l1_mldsa_pub, _) = capacity_verify::mldsa::keypair_from_seed(&l1_seed).unwrap();
        let ecdsa_sk = capacity_verify::ecdsa_p256::signing_key_from_seed(&l1_seed);
        let l1_p256_pub = capacity_verify::ecdsa_p256::public_key_sec1(&ecdsa_sk, false);

        // Seed the resolver under the pinned fingerprint (as main.rs does).
        let mut resolver = StaticManifestResolver::new();
        resolver.insert(
            FP,
            ResolvedManifestEntry {
                kid: KID.into(),
                algorithm: PROFILE_P256_MLDSA65.into(),
                public_key: l1_mldsa_pub.clone(),
                classical_public_key: l1_p256_pub,
                valid_from: Some(
                    chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2020, 1, 1, 0, 0, 0).unwrap(),
                ),
                valid_until: Some(
                    chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2099, 1, 1, 0, 0, 0).unwrap(),
                ),
            },
        );
        let verifier = IssuerVerifier {
            resolver: Arc::new(resolver),
            system_root_fingerprint: Arc::new(FP.to_string()),
            challenges: Arc::new(Default::default()),
        };

        // Issuer leaf key (tree_size 1, stable): root == leaf_hash, empty proof.
        let leaf_seed = [42u8; 32];
        let (leaf_pub, _) = capacity_verify::mldsa::keypair_from_seed(&leaf_seed).unwrap();
        let root = capacity_artifacts::capacity_evidence::operation_key_leaf_hash(&leaf_pub);

        // Binding signed by the system-domain L1 composite over its signing bytes.
        let binding = Level1AuthorizationBinding {
            system_id: "certcrypt".into(),
            rules_version: "rules/conformance".into(),
            system_root_fingerprint: FP.into(),
            authorized_role: "capacity_commitment_holder".into(),
            authorization_issuer_kid: KID.into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2099-01-01T00:00:00Z".into(),
            holder_key_set_root: root.clone(),
        };
        let digest = hex::encode(Sha3_256::digest(binding.signing_bytes().unwrap()));
        let sig =
            capacity_verify::composite::composite_sign_p256(&digest, &ecdsa_sk, &l1_seed).unwrap();

        // Fresh possession over a challenge, signed by the leaf key.
        // Anchored to now: the freshness check would refuse a hardcoded epoch.
        // The counter keeps every test's challenge distinct, so one test's cache
        // entry can never make another fail as a replay.
        static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let challenge = format!(
            "{}.test-{}",
            chrono::Utc::now().timestamp_millis(),
            NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let possession =
            capacity_verify::mldsa::sign_detached(&leaf_seed, req().message(&challenge).as_bytes())
                .unwrap();

        let mut proof = IssuerAuthProof {
            signed_level1: SignedLevel1Binding {
                level1_binding: binding,
                level1_signature: sig,
            },
            disclosure: OperationKeyDisclosure {
                leaf_index: 0,
                public_key_b64: B64.encode(&leaf_pub),
                inclusion_proof: vec![],
                tree_size: 1,
            },
            challenge,
            possession_b64: B64.encode(&possession),
        };
        mutate(&mut proof, &root);
        (verifier, proof)
    }

    /// The binding verifies, but it says it was issued in 2026 and the Level-1
    /// key that signed it was rotated out in 2021: a retired key signs nothing
    /// valid after its interval (`system-manifest/1` §7.5).
    #[test]
    fn rejects_a_binding_issued_after_its_key_was_rotated_out() {
        let (_, p) = make(|_, _| {});
        let l1_seed = [7u8; 32];
        let (l1_mldsa_pub, _) = capacity_verify::mldsa::keypair_from_seed(&l1_seed).unwrap();
        let ecdsa_sk = capacity_verify::ecdsa_p256::signing_key_from_seed(&l1_seed);
        let at = |y| chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, y, 1, 1, 0, 0, 0).unwrap();
        let mut resolver = StaticManifestResolver::new();
        resolver.insert(
            FP,
            ResolvedManifestEntry {
                kid: KID.into(),
                algorithm: PROFILE_P256_MLDSA65.into(),
                public_key: l1_mldsa_pub,
                classical_public_key: capacity_verify::ecdsa_p256::public_key_sec1(
                    &ecdsa_sk, false,
                ),
                valid_from: Some(at(2020)),
                valid_until: Some(at(2021)),
            },
        );
        let v = IssuerVerifier {
            resolver: Arc::new(resolver),
            system_root_fingerprint: Arc::new(FP.to_string()),
            challenges: Arc::new(Default::default()),
        };
        let err = verify_issuer_proof(&v, &p, &req()).expect_err("a retired key's late binding");
        assert!(err.contains("active interval"), "{err}");
    }

    #[test]
    fn accepts_a_valid_proof() {
        let (v, p) = make(|_, _| {});
        let scope = verify_issuer_proof(&v, &p, &req()).expect("valid proof must verify");
        assert_eq!(scope, p.signed_level1.level1_binding.holder_key_set_root);
    }

    #[test]
    fn rejects_wrong_fingerprint() {
        // Binding issued under a DIFFERENT fingerprint than the node pins.
        let (v, p) = make(|p, _| {
            p.signed_level1.level1_binding.system_root_fingerprint =
                "00000000000000000000000000000000000000000000000000000000000000ff".into();
        });
        assert!(
            verify_issuer_proof(&v, &p, &req()).is_err(),
            "wrong fingerprint must be rejected"
        );
    }

    #[test]
    fn rejects_bad_possession() {
        // Possession signature over a DIFFERENT challenge than the one presented.
        let (v, p) = make(|p, _| {
            let leaf_seed = [42u8; 32];
            let bad =
                capacity_verify::mldsa::sign_detached(&leaf_seed, b"other-challenge").unwrap();
            p.possession_b64 = B64.encode(&bad);
        });
        assert!(
            verify_issuer_proof(&v, &p, &req()).is_err(),
            "bad possession must be rejected"
        );
    }

    #[test]
    fn a_captured_proof_cannot_be_replayed() {
        // THE ATTACK THIS GUARD EXISTS FOR. An issuer necessarily hands its whole
        // proof to the node — that is how the node authenticates it. A malicious
        // node keeps a copy and re-presents it later, speaking as that issuer
        // without the issuer initiating anything: reading its operation history and
        // its dead-letter queue for as long as the binding lasts (valid_until is
        // years away). This test fails if the freshness/single-use check is ever
        // removed.
        let (v, p) = make(|_, _| {});
        assert!(
            verify_issuer_proof(&v, &p, &req()).is_ok(),
            "first use must be accepted"
        );
        assert!(
            verify_issuer_proof(&v, &p, &req()).is_err(),
            "the SAME proof must never verify twice"
        );
    }

    #[test]
    fn rejects_a_stale_challenge() {
        // Beyond the freshness window: this is what stops a proof captured before
        // the node last restarted (its cache is in-process, so age is the guard
        // that covers a cold cache).
        let (v, p) = make(|p, _| {
            let stale =
                chrono::Utc::now().timestamp_millis() - (CHALLENGE_MAX_SKEW_SECS + 60) * 1000;
            let leaf_seed = [42u8; 32];
            let challenge = format!("{stale}.stale");
            // Sign it properly — the point is that a CORRECTLY signed but old
            // challenge is refused, not that a bad signature is.
            let sig = capacity_verify::mldsa::sign_detached(
                &leaf_seed,
                req().message(&challenge).as_bytes(),
            )
            .unwrap();
            p.challenge = challenge;
            p.possession_b64 = B64.encode(&sig);
        });
        assert!(
            verify_issuer_proof(&v, &p, &req()).is_err(),
            "a challenge older than the window must be rejected"
        );
    }

    #[test]
    fn rejects_a_malformed_challenge() {
        // No `<millis>.<random>` shape → no freshness can be established. Refuse
        // rather than fall back to accepting it.
        let (v, p) = make(|p, _| {
            let leaf_seed = [42u8; 32];
            let challenge = "not-a-timestamp".to_string();
            let sig = capacity_verify::mldsa::sign_detached(
                &leaf_seed,
                req().message(&challenge).as_bytes(),
            )
            .unwrap();
            p.challenge = challenge;
            p.possession_b64 = B64.encode(&sig);
        });
        assert!(
            verify_issuer_proof(&v, &p, &req()).is_err(),
            "a challenge with no timestamp must be rejected"
        );
    }

    #[test]
    fn a_failed_proof_does_not_consume_its_challenge() {
        // Order matters: the cache is touched LAST. Otherwise an unauthenticated
        // caller could burn an issuer's challenge — or fill the cache — by sending
        // proofs that fail an earlier check.
        let cache = Arc::new(ChallengeCache::default());
        let (mut v, good) = make(|_, _| {});
        v.challenges = cache.clone();

        // Same challenge, broken possession signature.
        let mut bad = good.clone();
        bad.possession_b64 = B64.encode([0u8; 64]);
        let mut v_bad = v.clone();
        v_bad.challenges = cache.clone();
        assert!(
            verify_issuer_proof(&v_bad, &bad, &req()).is_err(),
            "bad proof must fail"
        );

        // The legitimate proof carrying that same challenge must still work.
        assert!(
            verify_issuer_proof(&v, &good, &req()).is_ok(),
            "a failed attempt must not consume the challenge"
        );
    }

    #[test]
    fn rejects_expired_binding() {
        // valid_until in the past → outside the validity window. The signature is
        // re-computed over the mutated binding so ONLY the window check fails.
        let (v, p) = make(|p, root| {
            let l1_seed = [7u8; 32];
            let ecdsa_sk = capacity_verify::ecdsa_p256::signing_key_from_seed(&l1_seed);
            p.signed_level1.level1_binding.valid_until = "2020-01-01T00:00:00Z".into();
            let _ = root;
            let digest = hex::encode(Sha3_256::digest(
                p.signed_level1.level1_binding.signing_bytes().unwrap(),
            ));
            p.signed_level1.level1_signature =
                capacity_verify::composite::composite_sign_p256(&digest, &ecdsa_sk, &l1_seed)
                    .unwrap();
        });
        assert!(
            verify_issuer_proof(&v, &p, &req()).is_err(),
            "expired binding must be rejected"
        );
    }

    #[test]
    fn rejects_leaf_not_in_root() {
        // A disclosure whose leaf is not the one committed by holder_key_set_root.
        let (v, p) = make(|p, _| {
            let other_seed = [99u8; 32];
            let (other_pub, _) = capacity_verify::mldsa::keypair_from_seed(&other_seed).unwrap();
            p.disclosure.public_key_b64 = B64.encode(&other_pub);
        });
        assert!(
            verify_issuer_proof(&v, &p, &req()).is_err(),
            "foreign leaf must be rejected"
        );
    }

    /// The production trust path: the L1 key comes from a quorum-signed
    /// system-foundation/1 statement, verified against the pinned fingerprint,
    /// and resolves only under the kid derived from it.
    #[test]
    fn verifies_through_a_signed_foundation() {
        use capacity_verify::foundation::{
            sign_foundation_statement, FoundationManifestResolver, FoundationRootMember,
            FoundationStatementInput,
        };

        let l1_seed = [7u8; 32];
        let (l1_mldsa_pub, _) = capacity_verify::mldsa::keypair_from_seed(&l1_seed).unwrap();
        let l1_ecdsa = capacity_verify::ecdsa_p256::signing_key_from_seed(&l1_seed);
        let root: Vec<_> = [21u8, 22]
            .iter()
            .map(|s| {
                let seed = [*s; 32];
                let (pk, _) = capacity_verify::mldsa::keypair_from_seed(&seed).unwrap();
                (
                    capacity_verify::ecdsa_p256::signing_key_from_seed(&seed),
                    pk,
                    seed,
                )
            })
            .collect();
        let members: Vec<_> = root
            .iter()
            .zip(["m0", "m1"])
            .map(|((p256, pk, seed), kid)| FoundationRootMember {
                member_kid: kid,
                p256_signing_key: p256,
                mldsa_public_key: pk,
                mldsa_secret_key: seed,
            })
            .collect();
        let statement = sign_foundation_statement(&FoundationStatementInput {
            foundation_statement_id: "node-auth-test",
            system_id: "certcrypt",
            bootstrap_kid: "root-test",
            bootstrap_valid_from: "2026-01-01T00:00:00Z",
            quorum_k: 2,
            members: &members,
            capacity_key_p256: &capacity_verify::ecdsa_p256::public_key_sec1(&l1_ecdsa, false),
            capacity_key_mldsa: &l1_mldsa_pub,
            published_rules_versions: &[],
            statement_issued_at: "2026-01-01T00:00:00Z",
        })
        .unwrap();
        let srf = statement["system_root_fingerprint"]
            .as_str()
            .unwrap()
            .to_owned();
        let resolver = FoundationManifestResolver::from_statement_bytes(
            &serde_json::to_vec(&statement).unwrap(),
            &srf,
            None,
        )
        .unwrap();
        let kid = resolver.level1_kid().to_owned();
        let verifier = IssuerVerifier {
            resolver: Arc::new(resolver),
            system_root_fingerprint: Arc::new(srf.clone()),
            challenges: Arc::new(Default::default()),
        };

        // Re-issue the fixture's proof under the foundation's root and kid,
        // re-signed by the L1 key the statement publishes.
        let resign = |p: &mut IssuerAuthProof, kid: &str, signer_seed: [u8; 32]| {
            let b = &mut p.signed_level1.level1_binding;
            b.system_root_fingerprint = srf.clone();
            b.authorization_issuer_kid = kid.into();
            let digest = hex::encode(Sha3_256::digest(b.signing_bytes().unwrap()));
            let ecdsa = capacity_verify::ecdsa_p256::signing_key_from_seed(&signer_seed);
            p.signed_level1.level1_signature =
                capacity_verify::composite::composite_sign_p256(&digest, &ecdsa, &signer_seed)
                    .unwrap();
        };

        let (_, mut p) = make(|_, _| {});
        resign(&mut p, &kid, l1_seed);
        assert!(
            verify_issuer_proof(&verifier, &p, &req()).is_ok(),
            "foundation key must verify"
        );

        let (_, mut p) = make(|_, _| {});
        resign(&mut p, "some-other-kid", l1_seed);
        assert!(
            verify_issuer_proof(&verifier, &p, &req()).is_err(),
            "a kid the foundation does not resolve must be refused"
        );

        let (_, mut p) = make(|_, _| {});
        resign(&mut p, &kid, [8u8; 32]);
        assert!(
            verify_issuer_proof(&verifier, &p, &req()).is_err(),
            "a binding signed by any key but the foundation's must be refused"
        );
    }
}
