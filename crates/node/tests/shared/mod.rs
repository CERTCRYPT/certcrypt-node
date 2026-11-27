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

//! Issuer-auth test material shared across the node's integration tests.
//!
//! A synthetic L1 seed, fingerprint and kid, plus a verifier seeded with them and a
//! minter for a valid `x-certcrypt-issuer-auth` header. Kept here so a test
//! that only needs to get *past* authentication does not restate the crypto.

#![allow(dead_code)] // Not every integration test needs every helper.

pub mod submission_set_fixture;

use std::sync::Arc;

use serde_json::json;

/// Synthetic Level-1 seed for tests.
pub const L1_SEED: [u8; 32] = [7u8; 32];
/// Synthetic system-root fingerprint the static resolver is seeded under. Any
/// 64-hex value works; this one names no real deployment.
pub const FP: &str = "abababababababababababababababababababababababababababababababab";
/// Key id the manifest resolves the L1 composite under.
pub const KID: &str = "test-l1-kid";
/// A holder key-set leaf seed for tests that just need to authenticate.
pub const ISSUER_SEED: [u8; 32] = [11u8; 32];
/// Header name the node reads the issuer proof from.
pub const ISSUER_AUTH_HEADER: &str = "x-certcrypt-issuer-auth";

/// A verifier anchored on the synthetic L1 material, so a proof minted by
/// [`issuer_auth_header`] verifies against it.
pub fn issuer_verifier() -> certcrypt_node::auth::IssuerVerifier {
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
/// every call after the first fail as a replay — and would quietly stop testing
/// what it claims to test.
pub fn issuer_auth_header(seed: &[u8; 32], request: &RequestBinding) -> String {
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
    // check parses. The counter keeps concurrent callers from colliding.
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let challenge = format!(
        "{}.shared-{}",
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

/// An operator identity plus a recognition credential for the node. Self-signed
/// over the operator's real public key: the stub issuance services in these tests do not
/// verify it, and the node needs SOME credential to assemble the mandatory
/// recognition proof.
pub fn operator_material() -> (
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

/// The `holder_key_set_root` an issuer authenticating with `seed` is scoped to
/// — the `contract_id` the node files its outbox entries and records under.
pub fn holder_key_set_root(seed: &[u8; 32]) -> String {
    let (leaf_pub, _) = capacity_verify::mldsa::keypair_from_seed(seed).unwrap();
    capacity_artifacts::capacity_evidence::operation_key_leaf_hash(&leaf_pub)
}

pub use certcrypt_node::auth::RequestBinding;

/// The request a built `reqwest` request is, as the node will see it — what an
/// issuer proof for it must be bound to (host, method, path and query, body).
pub fn request_binding(builder: &reqwest::RequestBuilder) -> RequestBinding {
    use sha3::{Digest, Sha3_256};
    let req = builder
        .try_clone()
        .expect("a cloneable request")
        .build()
        .expect("a valid request");
    let url = req.url();
    let host = match url.port() {
        Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    let path_and_query = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or_default();
    RequestBinding {
        host,
        method: req.method().as_str().to_string(),
        path_and_query,
        body_sha3_hex: hex::encode(Sha3_256::digest(body)),
    }
}

/// `builder` with a fresh issuer proof for `seed`, bound to that very request.
/// Call it last, once the body is set.
pub fn signed(builder: reqwest::RequestBuilder, seed: &[u8; 32]) -> reqwest::RequestBuilder {
    let request = request_binding(&builder);
    builder.header(ISSUER_AUTH_HEADER, issuer_auth_header(seed, &request))
}

/// The issuer proof for `seed` on a request not built yet: `method` on `url`
/// with `body`. For a header that has to be computed ahead of the request.
pub fn issuer_auth_for(seed: &[u8; 32], method: &str, url: &str, body: &[u8]) -> String {
    let builder = reqwest::Client::new()
        .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url)
        .body(body.to_vec());
    issuer_auth_header(seed, &request_binding(&builder))
}
