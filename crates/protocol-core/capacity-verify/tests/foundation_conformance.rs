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

//! `system-foundation/1` parity with the conformance vectors.
//!
//! Every `system-foundation.json` in the contract is run through
//! [`verify_system_foundation`] and, pinned to the published bootstrap
//! fingerprint of `rules/conformance`, through [`FoundationManifestResolver`].
//! A vector whose expected result names a foundation check must be rejected
//! with exactly that check; every other vector must be accepted, exposing the
//! very key bytes the statement publishes.
//!
//! The successor-binding cases at the end mirror the reference verifier's own
//! tests over P009 and QN4: what the vectors alone do not pin.

use base64::Engine as _;
use capacity_verify::foundation::{verify_system_foundation_value, FoundationError};
use capacity_verify::{
    derive_kid, verify_system_foundation, FoundationManifestResolver, ManifestResolver,
};
use serde_json::Value;
use std::path::{Path, PathBuf};

const ENV_FIXTURES_DIR: &str = "CERTCRYPT_CONFORMANCE_FIXTURES_DIR";
const ENV_ALLOW_MISSING: &str = "CERTCRYPT_ALLOW_MISSING_CONFORMANCE";

/// The published bootstrap fingerprint of `rules/conformance`: the root every
/// valid vector is issued under, and the pin a verifier holds for it.
const CONFORMANCE_BOOTSTRAP: &str =
    "4641cb3850fdfde06875bed9382b2afeb2a108ac48ef32d4e196d456a0059635";

/// Checks this verifier answers for. Any other failed check id in a vector is
/// about a later phase, and the statement itself must verify.
const STATEMENT_CHECKS: [&str; 6] = [
    "FOUNDATION_PROFILE_VALID",
    "FOUNDATION_SYSTEM_ID_VALID",
    "FOUNDATION_FINGERPRINT_RECOMPUTED",
    "FOUNDATION_SIGNATURE_VALID",
    "FOUNDATION_SUCCESSOR_QUORUM_VALID",
    "FOUNDATION_EQUIVOCATION_DETECTED",
];
const PIN_CHECK: &str = "FOUNDATION_BOOTSTRAP_MATCHES_RULES";
/// The statement id the conformance domain registers for its bootstrap.
const CONFORMANCE_STATEMENT_ID: &str = "test-foundation-P001-zero-data";
/// SHA3-256(JCS(unsigned payload)) of that statement: the one signed content
/// the conformance bootstrap admits (`F004` is a second statement over it).
const CONFORMANCE_PAYLOAD_DIGEST: &str =
    "5bf125fdf89aa617ab4a28fe115d8cf5850bff5aba752544eac56b9edfc9e58b";

/// Locate the contract's `fixtures/`, or FAIL (absence verifies nothing).
fn fixtures_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_FIXTURES_DIR) {
        let dir = PathBuf::from(dir);
        assert!(
            dir.is_dir(),
            "{ENV_FIXTURES_DIR} is not a directory: {}",
            dir.display()
        );
        return Some(dir);
    }
    // Walk up: this crate can sit at different depths depending on the checkout.
    let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while here.pop() {
        let candidate = here.join("certcrypt-conformance/fixtures");
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    if std::env::var(ENV_ALLOW_MISSING).as_deref() == Ok("1") {
        eprintln!(
            "WARNING: conformance suite not found and {ENV_ALLOW_MISSING}=1 — \
             system-foundation parity was NOT verified in this run"
        );
        return None;
    }
    panic!(
        "conformance contract not found: set ${ENV_FIXTURES_DIR}, check out \
         certcrypt-conformance alongside this repository, or set {ENV_ALLOW_MISSING}=1 \
         to acknowledge running without it"
    );
}

/// Every `<suite>/<case>/artifacts/system-foundation.json`, with its case dir.
fn vectors(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for suite in ["conformance", "adversarial"] {
        let Ok(cases) = std::fs::read_dir(root.join(suite)) else {
            continue;
        };
        for case in cases.flatten() {
            let statement = case.path().join("artifacts/system-foundation.json");
            if statement.is_file() {
                out.push((
                    format!("{suite}/{}", case.file_name().to_string_lossy()),
                    case.path(),
                ));
            }
        }
    }
    out.sort();
    out
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn b64(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap())
        .unwrap()
}

#[test]
fn every_conformance_foundation_matches_its_expected_result() {
    let Some(root) = fixtures_dir() else { return };
    let cases = vectors(&root);
    assert!(
        cases.len() >= 80,
        "expected the full vector set, found {}",
        cases.len()
    );

    let (mut accepted, mut rejected) = (0, 0);
    for (name, dir) in &cases {
        let raw = std::fs::read(dir.join("artifacts/system-foundation.json")).unwrap();
        let statement: Value = serde_json::from_slice(&raw).unwrap();
        let expected = read_json(&dir.join("expected-result.json"));
        let failed: Vec<&str> = expected["failed_check_ids"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();

        let verdict = verify_system_foundation(&raw);
        if let Some(check) = failed.iter().find(|c| STATEMENT_CHECKS.contains(c)) {
            let err = verdict.expect_err(name);
            assert_eq!(
                err.check_id(),
                *check,
                "{name}: rejected for the wrong reason: {err}"
            );
            rejected += 1;
            continue;
        }
        let verified = verdict.unwrap_or_else(|e| panic!("{name}: valid statement rejected: {e}"));

        let pinned = FoundationManifestResolver::from_statement_bytes_pinned(
            &raw,
            CONFORMANCE_BOOTSTRAP,
            Some(CONFORMANCE_STATEMENT_ID),
            Some(CONFORMANCE_PAYLOAD_DIGEST),
        );
        if failed.contains(&PIN_CHECK) {
            let err = pinned.expect_err(name);
            assert_eq!(err.check_id(), PIN_CHECK, "{name}: {err}");
            rejected += 1;
            continue;
        }
        let resolver = pinned.unwrap_or_else(|e| panic!("{name}: {e}"));

        // The exposed key is exactly what the statement publishes, under the
        // pinned root and the kid derived from its ML-DSA component.
        let mldsa = b64(&statement["system_domain_capacity_key_mldsa_b64"]);
        let p256 = b64(&statement["system_domain_capacity_key_p256_b64"]);
        assert_eq!(verified.capacity_key_mldsa, mldsa, "{name}");
        assert_eq!(verified.capacity_key_p256, p256, "{name}");
        let entry = resolver
            .resolve(CONFORMANCE_BOOTSTRAP, &derive_kid(&mldsa))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(entry.public_key, mldsa, "{name}");
        assert_eq!(entry.classical_public_key, p256, "{name}");
        accepted += 1;
    }
    eprintln!("system-foundation vectors: {accepted} accepted, {rejected} rejected");
    assert!(accepted > 0 && rejected > 0);
}

fn load(root: &Path, case: &str) -> Value {
    read_json(&root.join(case).join("artifacts/system-foundation.json"))
}

fn check(statement: &Value) -> Result<(), &'static str> {
    verify_system_foundation_value(statement)
        .map(|_| ())
        .map_err(|e: FoundationError| e.check_id())
}

/// Reverse the member order of every object — JCS must not care.
fn reorder(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(reorder).collect()),
        Value::Object(o) => {
            let mut entries: Vec<_> = o.iter().collect();
            entries.reverse();
            let mut out = serde_json::Map::new();
            for (k, x) in entries {
                out.insert(k.clone(), reorder(x));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

#[test]
fn successor_observations_follow_the_reference_rules() {
    let Some(root) = fixtures_dir() else { return };
    let p009 = load(&root, "conformance/P009");
    let qn4 = load(&root, "adversarial/QN4");

    // The published valid rotation is accepted.
    assert_eq!(check(&p009), Ok(()));

    // The same authenticated observation twice: repetition is not equivocation.
    let mut f = p009.clone();
    let obs = f["successor_binding_observations"][0].clone();
    f["successor_binding_observations"] = Value::Array(vec![obs.clone(), obs]);
    assert_eq!(check(&f), Ok(()));

    // An observation naming a predecessor state the statement does not establish.
    let mut f = p009.clone();
    f["successor_binding_observations"][0]["successor_binding"]
        ["predecessor_manifest_fingerprint"] = Value::String("00".repeat(32));
    assert_eq!(check(&f), Err("FOUNDATION_SUCCESSOR_QUORUM_VALID"));

    // A member outside the closed §9 payload.
    let mut f = p009.clone();
    f["successor_binding_observations"][0]["successor_binding"]["note"] =
        Value::String("extra".into());
    assert_eq!(check(&f), Err("FOUNDATION_SUCCESSOR_QUORUM_VALID"));

    // An empty list is not "no observations".
    let mut f = p009.clone();
    f["successor_binding_observations"] = Value::Array(vec![]);
    assert_eq!(check(&f), Err("FOUNDATION_SUCCESSOR_QUORUM_VALID"));

    // The quorum is over JCS bytes: member order does not matter.
    let mut f = p009.clone();
    f["successor_binding_observations"] = reorder(&p009["successor_binding_observations"]);
    assert_eq!(check(&f), Ok(()));

    // Equivocation is detected regardless of member order.
    let mut f = qn4.clone();
    let list = qn4["successor_binding_observations"].as_array().unwrap();
    f["successor_binding_observations"] = Value::Array(vec![list[0].clone(), reorder(&list[1])]);
    assert_eq!(check(&f), Err("FOUNDATION_EQUIVOCATION_DETECTED"));

    // An unauthenticated observation cannot establish equivocation.
    let mut f = qn4.clone();
    f["successor_binding_observations"][1]["predecessor_signatures"] = Value::Array(vec![]);
    assert_eq!(check(&f), Err("FOUNDATION_SUCCESSOR_QUORUM_VALID"));
}
