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

//! ECDSA P-256 signing parity: the signature bytes themselves.
//!
//! Every verifier accepts any valid low-s signature, so a signer whose nonce
//! differs still verifies everywhere and no verdict test can see it. What it
//! breaks is reproducibility: the same key over the same message would yield
//! different bytes here and in an issuer SDK. The family
//! `ecdsa-p256-deterministic` pins the nonce (RFC 6979 with H = SHA3-256), so
//! this signer is held to it byte for byte.
//!
//! Keys are taken from `scalar_hex`, which the family always writes out, so this
//! test signs without deriving; the public point is still compared, so a key read
//! wrongly cannot pass by signing under some other scalar.

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

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
             ECDSA P-256 signing parity was NOT verified in this run"
        );
        return None;
    }
    panic!(
        "conformance contract not found: neither ${ENV_FIXTURES_DIR} nor a sibling \
         certcrypt-conformance checkout ({}).\n\
         This crate emits the ECDSA component of every composite signature here, so a \
         run without the contract verifies nothing. Set {ENV_ALLOW_MISSING}=1 \
         to acknowledge running without it.",
        sibling.display()
    );
}

fn load(path: PathBuf) -> serde_json::Value {
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn signing_key(keys: &serde_json::Value, key_ref: &str) -> p256::ecdsa::SigningKey {
    let key = &keys[key_ref];
    let scalar = hex::decode(key["scalar_hex"].as_str().expect("scalar_hex")).expect("hex");
    let sk = p256::ecdsa::SigningKey::from_slice(&scalar)
        .unwrap_or_else(|e| panic!("key '{key_ref}': scalar is not a valid P-256 key: {e}"));
    let public = capacity_verify::ecdsa_p256::public_key_sec1(&sk, false);
    assert_eq!(
        B64.encode(&public),
        key["expected_pub_p256_b64"]
            .as_str()
            .expect("expected_pub_p256_b64"),
        "key '{key_ref}': the scalar does not give the public point the contract pins"
    );
    sk
}

/// Each message vector: the signer's bytes equal the contract's, exactly.
#[test]
fn ecdsa_p256_signatures_match_the_contract() {
    let Some(dir) = primitives_dir() else {
        return;
    };
    let v = load(dir.join("ecdsa-p256-deterministic/vectors.json"));
    let keys = &v["keys"];
    let vectors = v["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "the family carries no vectors");

    for vec in vectors {
        let name = vec["name"].as_str().unwrap_or("?");
        let key_ref = vec["key"].as_str().expect("key");
        let sk = signing_key(keys, key_ref);
        let message = hex::decode(vec["message_hex"].as_str().expect("message_hex")).expect("hex");

        assert_eq!(
            hex::encode(<sha3::Sha3_256 as sha3::Digest>::digest(&message)),
            vec["expected_prehash_sha3_256_hex"].as_str().unwrap(),
            "'{name}': prehash diverged"
        );

        let sig = capacity_verify::ecdsa_p256::sign_raw_rs_64(&sk, &message);
        assert_eq!(
            hex::encode(sig),
            vec["expected_sig_hex"].as_str().unwrap(),
            "'{name}': signature bytes diverged from the contract — the RFC 6979 nonce \
             must use HMAC-SHA3-256, and low-s must be applied"
        );
        assert_eq!(
            B64.encode(sig),
            vec["expected_sig_b64"].as_str().unwrap(),
            "'{name}': base64 form diverged"
        );
        capacity_verify::ecdsa_p256::verify_raw_rs_64(
            &capacity_verify::ecdsa_p256::public_key_sec1(&sk, false),
            &message,
            &sig,
        )
        .unwrap_or_else(|e| panic!("'{name}': the contract's signature does not verify: {e}"));
    }
}

/// Each composite case: the ECDSA component as it goes on the wire, signed over
/// the M′ this crate frames.
#[test]
fn ecdsa_p256_composite_components_match_the_contract() {
    let Some(dir) = primitives_dir() else {
        return;
    };
    let v = load(dir.join("ecdsa-p256-deterministic/vectors.json"));
    let keys = &v["keys"];
    let cases = v["composite_cases"]
        .as_array()
        .expect("composite_cases array");
    assert!(!cases.is_empty(), "the family carries no composite cases");

    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let sk = signing_key(keys, case["key"].as_str().expect("key"));
        let m_prime = capacity_verify::composite::composite_m_prime(
            case["composite_alg_id"].as_str().expect("composite_alg_id"),
            case["payload_canon_digest_hex"]
                .as_str()
                .expect("payload_canon_digest_hex"),
        );
        assert_eq!(
            hex::encode(&m_prime),
            case["expected_m_prime_hex"].as_str().unwrap(),
            "'{name}': M′ diverged"
        );

        let component = &case["expected_ecdsa_component"];
        assert_eq!(component["alg"].as_str(), Some("ECDSA-P256-SHA3-256"));
        assert_eq!(component["encoding"].as_str(), Some("raw-rs-64"));
        assert_eq!(component["low_s"].as_bool(), Some(true));

        let sig = capacity_verify::ecdsa_p256::sign_raw_rs_64(&sk, &m_prime);
        assert_eq!(
            B64.encode(sig),
            component["sig_b64"].as_str().unwrap(),
            "'{name}': composite ECDSA component diverged from the contract"
        );
    }
}
