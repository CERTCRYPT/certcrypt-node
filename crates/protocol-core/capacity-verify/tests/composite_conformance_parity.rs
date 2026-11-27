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

//! Composite signature parity: the framing, and what verification REFUSES.
//!
//! This crate carries `composite_m_prime` and `verify_composite`, so a change
//! here is not one implementation diverging from another — it is the rule itself
//! moving under every caller at once. The contract is what says whether the
//! change was intended.
//!
//! Two halves, and the second is the one that needs saying: a valid signature
//! proves the maths works and says nothing about what the code does with an
//! invalid one. The refusals are policy this code enforces — the post-quantum
//! floor above all — not properties the cryptography provides. Nothing else
//! catches them.
//!
//! What is deliberately NOT attempted here: showing that no forged signature ever
//! verifies. That belongs to ECDSA and ML-DSA, comes from the linked library, and
//! no fixture can establish it.

use std::path::PathBuf;

/// Points at the conformance repo's `fixtures/` directory, when it is not a
/// sibling checkout of certcrypt-conformance.
const ENV_FIXTURES_DIR: &str = "CERTCRYPT_CONFORMANCE_FIXTURES_DIR";

/// Opt-out for a contributor with no conformance checkout. Never for CI.
const ENV_ALLOW_MISSING: &str = "CERTCRYPT_ALLOW_MISSING_CONFORMANCE";

/// Locate the contract's `fixtures/primitives`, or FAIL.
///
/// Absence is an error, not a skip: a run that cannot find the contract has
/// verified nothing, and reporting that as success is how a divergence ships.
fn primitives_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_FIXTURES_DIR) {
        let dir = PathBuf::from(dir).join("primitives");
        assert!(
            dir.is_dir(),
            "{ENV_FIXTURES_DIR} does not contain a primitives/ directory: {}",
            dir.display()
        );
        return Some(dir);
    }
    // Walk up looking for a sibling checkout rather than assuming a fixed depth:
    // this crate can be checked out inside other trees, and the folder sits at a
    // different level in each. Assuming one depth would report "contract not
    // found" on a machine that has it.
    let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut sibling = here.join("certcrypt-conformance/fixtures/primitives");
    while here.pop() {
        let candidate = here.join("certcrypt-conformance/fixtures/primitives");
        if candidate.is_dir() {
            return Some(candidate);
        }
        sibling = candidate;
    }
    if std::env::var(ENV_ALLOW_MISSING).as_deref() == Ok("1") {
        eprintln!(
            "WARNING: conformance suite not found and {ENV_ALLOW_MISSING}=1 — \
             composite parity was NOT verified in this run"
        );
        return None;
    }
    panic!(
        "conformance contract not found: neither ${ENV_FIXTURES_DIR} nor a sibling \
         certcrypt-conformance checkout ({}).\n\
         This crate defines the composite framing that every signature here is made \
         under, so a run without the contract verifies nothing. Set {ENV_ALLOW_MISSING}=1 \
         to acknowledge running without it.",
        sibling.display()
    );
}

fn load(path: PathBuf) -> serde_json::Value {
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// M′ — the message both components sign — must be framed byte-for-byte as the
/// contract fixes it.
///
/// This is the last deterministic step before signing, and where a divergence
/// does the most damage: two implementations framing M′ differently each verify
/// their OWN signatures perfectly and neither verifies the other's. Every local
/// test passes on both sides.
#[test]
fn composite_m_prime_matches_the_contract() {
    let Some(dir) = primitives_dir() else {
        return;
    };
    let v = load(dir.join("composite-m-prime/vectors.json"));

    for vec in v["vectors"].as_array().expect("vectors array") {
        let label = vec["label"].as_str().unwrap_or("?");
        let alg = vec["composite_alg_id"].as_str().expect("composite_alg_id");
        let digest = vec["payload_canon_digest_hex"]
            .as_str()
            .expect("payload_canon_digest_hex");

        let m = capacity_verify::composite::composite_m_prime(alg, digest);
        assert_eq!(
            hex::encode(&m),
            vec["expected_m_prime_hex"].as_str().unwrap(),
            "composite-m-prime '{label}': framing diverged — domain prefix, separators, \
             or the order of the parts"
        );
        assert_eq!(
            m.len(),
            vec["expected_m_prime_len"].as_u64().unwrap() as usize,
            "composite-m-prime '{label}': length diverged"
        );
    }

    // The property the profile is in the framing FOR: without it, a signature
    // made under one profile could be reinterpreted under another.
    let a = capacity_verify::composite::composite_m_prime(
        capacity_artifacts::composite_sig::PROFILE_P256_MLDSA65,
        &"a".repeat(64),
    );
    let b = capacity_verify::composite::composite_m_prime(
        "certcrypt-composite-ed25519-mldsa65-v1",
        &"a".repeat(64),
    );
    assert_ne!(
        a, b,
        "the composite profile must change M′ — omitting it makes a signature \
         reinterpretable across profiles"
    );
}

/// Every refusal in the contract's table must be a refusal here too.
///
/// The load-bearing case is `missing-mldsa-component`: its classical half
/// verifies perfectly, so an implementation treating the post-quantum floor as
/// optional accepts it while every cryptographic check it runs passes. This crate
/// is where that policy lives.
#[test]
fn composite_verification_refusals_match_the_contract() {
    let Some(dir) = primitives_dir() else {
        return;
    };
    let v = load(dir.join("composite-verification/vectors.json"));

    let digest = v["payload_canon_digest_hex"]
        .as_str()
        .expect("payload digest");
    let b64 = base64::engine::general_purpose::STANDARD;
    let p256_pub = base64::Engine::decode(
        &b64,
        v["system_domain_p256_public_key_b64"].as_str().unwrap(),
    )
    .expect("p256 key is base64");
    let mldsa_pub = base64::Engine::decode(
        &b64,
        v["system_domain_mldsa_public_key_b64"].as_str().unwrap(),
    )
    .expect("mldsa key is base64");

    let mut accepted = 0usize;
    let mut refused = 0usize;
    for case in v["cases"].as_array().expect("cases array") {
        let label = case["label"].as_str().unwrap_or("?");
        let expected_alg = case["expected_composite_alg_id"]
            .as_str()
            .expect("expected_composite_alg_id");
        // The composite object has exactly alg, mode and signatures, and the
        // wire type refuses unknown component members: a signature of any other
        // shape does not parse, which is a refusal.
        let exact_object = case["signature"].as_object().is_some_and(|o| {
            o.len() == 3
                && ["alg", "mode", "signatures"]
                    .iter()
                    .all(|k| o.contains_key(*k))
        });
        let parsed = serde_json::from_value::<
            capacity_artifacts::composite_sig::CompositeSignatureWire,
        >(case["signature"].clone())
        .ok()
        .filter(|_| exact_object);

        // A case may present the classical key in another encoding.
        let classical = match case["classical_public_key_b64"].as_str() {
            Some(k) => base64::Engine::decode(&b64, k).expect("case key is base64"),
            None => p256_pub.clone(),
        };
        let got = match &parsed {
            Some(sig) => {
                // Rebuilt per case: the borrow struct is not Copy.
                let keys = capacity_verify::composite::CompositePublicKeys {
                    classical_pub: &classical,
                    mldsa_pub: &mldsa_pub,
                };
                capacity_verify::composite::verify_composite(expected_alg, digest, sig, keys)
                    .map_err(|e| e.to_string())
            }
            None => Err("signature does not have the shape of the composite wire object".into()),
        };

        match case["expected_outcome"].as_str().expect("expected_outcome") {
            "accepted" => {
                accepted += 1;
                got.unwrap_or_else(|e| {
                    panic!("case '{label}': this crate rejects a composite the contract pins as valid: {e}")
                });
            }
            "rejected" => {
                refused += 1;
                assert!(
                    got.is_err(),
                    "case '{label}': this crate ACCEPTS a composite the contract refuses — {}",
                    case["why"].as_str().unwrap_or("")
                );
            }
            other => panic!("case '{label}': unknown expected_outcome {other}"),
        }
    }

    // A table of only-positives, or only-negatives, would pass vacuously while
    // pinning nothing about the boundary between them.
    assert!(
        accepted >= 1 && refused >= 1,
        "the refusal table must carry both a valid case and refusals \
         (accepted={accepted}, refused={refused})"
    );
}
