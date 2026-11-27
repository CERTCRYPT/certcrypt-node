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

//! `operator.domain-binding/1` against the contract's `operator-domain-binding`
//! family: the part this crate fixes.
//!
//! This crate owns the bytes of a statement — the member set, the signed
//! payload, the signed message with its domain-separation prefix, the digest —
//! the canonical host name, and every check that needs neither a signature
//! nor state (`validate_structure`). The ML-DSA-65 signature, the validity
//! window at the current instant and the Public Suffix List rule live with the
//! callers, and are held to the same vectors in their own tests. For those
//! cases this file asserts the opposite: that the checks here do NOT refuse a
//! statement whose only defect is one of them, so no rule is enforced twice
//! under two readings.

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use capacity_artifacts::operator_domain_binding::{
    normalize_domain, parse_instant, validate_domain_ascii, DomainBindingInputs,
    OperatorDomainBindingV1, WellKnownBindings, BIND_MAX_VALIDITY_DAYS,
    DOMAIN_BINDING_ARTIFACT_TYPE, DOMAIN_BINDING_METHOD_HTTPS_WELL_KNOWN,
    DOMAIN_BINDING_SIGNING_PREFIX, ISSUED_AT_FUTURE_TOLERANCE_SECONDS, SEQUENCE_MAX,
    WELL_KNOWN_MAX_BYTES, WELL_KNOWN_MAX_ENTRIES, WELL_KNOWN_PATH,
};
use capacity_artifacts::operator_recognition::{derive_operator_id, OPERATOR_KEY_ALG_ACTIVE};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

/// Points at the conformance repo's `fixtures/` directory, when it is not a
/// sibling checkout of certcrypt-conformance.
const ENV_FIXTURES_DIR: &str = "CERTCRYPT_CONFORMANCE_FIXTURES_DIR";

/// Opt-out for a contributor with no conformance checkout. Never for CI.
const ENV_ALLOW_MISSING: &str = "CERTCRYPT_ALLOW_MISSING_CONFORMANCE";

/// Locate the family's directory, or FAIL: a run that cannot find the contract
/// has verified nothing.
fn family_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_FIXTURES_DIR) {
        let dir = PathBuf::from(dir).join("primitives/operator-domain-binding");
        assert!(dir.is_dir(), "{} is missing", dir.display());
        return Some(dir);
    }
    let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while here.pop() {
        let candidate =
            here.join("certcrypt-conformance/fixtures/primitives/operator-domain-binding");
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    if std::env::var(ENV_ALLOW_MISSING).as_deref() == Ok("1") {
        eprintln!(
            "WARNING: conformance suite not found and {ENV_ALLOW_MISSING}=1 — \
             operator-domain-binding was NOT verified in this run"
        );
        return None;
    }
    panic!(
        "conformance contract not found: neither ${ENV_FIXTURES_DIR} nor a sibling \
         certcrypt-conformance checkout. Set {ENV_ALLOW_MISSING}=1 to acknowledge running \
         without it."
    );
}

fn load(dir: &std::path::Path, name: &str) -> Value {
    let path = dir.join(name);
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn instant(v: &Value, key: &str) -> chrono::DateTime<chrono::Utc> {
    s(v, key).parse().expect("an RFC 3339 instant")
}

#[test]
fn constants_match_the_contract() {
    let Some(dir) = family_dir() else { return };
    let c = &load(&dir, "vectors.json")["constants"];
    assert_eq!(s(c, "artifact_type"), DOMAIN_BINDING_ARTIFACT_TYPE);
    assert_eq!(
        s(c, "domain_binding_method"),
        DOMAIN_BINDING_METHOD_HTTPS_WELL_KNOWN
    );
    assert_eq!(s(c, "signature_alg"), OPERATOR_KEY_ALG_ACTIVE);
    assert_eq!(s(c, "signing_prefix"), DOMAIN_BINDING_SIGNING_PREFIX);
    assert_eq!(s(c, "well_known_path"), WELL_KNOWN_PATH);
    assert_eq!(c["well_known_max_bytes"], WELL_KNOWN_MAX_BYTES as u64);
    assert_eq!(c["well_known_max_entries"], WELL_KNOWN_MAX_ENTRIES as u64);
    assert_eq!(c["bind_max_validity_days"], BIND_MAX_VALIDITY_DAYS);
    assert_eq!(
        c["issued_at_future_tolerance_seconds"],
        ISSUED_AT_FUTURE_TOLERANCE_SECONDS
    );
    assert_eq!(s(c, "sequence_max"), SEQUENCE_MAX.to_string());
}

/// From the contract's inputs, `unsigned` must produce exactly the pinned
/// payload, message, digest and canonical artifact.
#[test]
fn construction_reproduces_the_pinned_bytes() {
    let Some(dir) = family_dir() else { return };
    let v = load(&dir, "vectors.json");
    for k in v["keys"].as_array().expect("keys") {
        let pk = B64.decode(s(k, "public_key_b64")).expect("base64 key");
        assert_eq!(
            derive_operator_id(&pk),
            s(k, "operator_id"),
            "key {}",
            s(k, "label")
        );
    }
    for case in v["construction"]["cases"].as_array().expect("cases") {
        let label = s(case, "label");
        let i = &case["inputs"];
        let e = &case["expected"];
        let key = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["label"] == i["operator_key"])
            .expect("key of the case");
        let mut st = OperatorDomainBindingV1::unsigned(&DomainBindingInputs {
            intent: s(i, "intent").into(),
            operator_public_key_b64: s(key, "public_key_b64").into(),
            domain: s(i, "domain").into(),
            sequence: i["sequence"].as_u64().expect("sequence"),
            issued_at: instant(i, "issued_at"),
            valid_until: instant(i, "valid_until"),
        })
        .unwrap_or_else(|e| panic!("{label}: unsigned refused the contract's inputs: {e}"));
        assert_eq!(
            st.domain_ascii,
            s(e, "domain_ascii"),
            "{label}: domain_ascii"
        );
        assert_eq!(st.operator_id, s(e, "operator_id"), "{label}: operator_id");
        let payload = st.signed_payload_jcs().unwrap();
        assert_eq!(
            String::from_utf8(payload.clone()).unwrap(),
            s(e, "signed_payload_jcs_utf8"),
            "{label}: signed payload diverged"
        );
        assert_eq!(
            hex::encode(st.statement_digest().unwrap()),
            s(e, "statement_digest_hex"),
            "{label}: statement digest"
        );
        assert_eq!(
            hex::encode(Sha3_256::digest(&payload)),
            s(e, "statement_digest_hex")
        );
        let msg = st.signing_message().unwrap();
        assert_eq!(
            String::from_utf8(msg.clone()).unwrap(),
            s(e, "signing_message_utf8"),
            "{label}: signed message diverged (prefix or payload)"
        );
        assert_eq!(
            hex::encode(Sha3_256::digest(&msg)),
            s(e, "signing_message_sha3_256_hex")
        );
        st.signature_b64 = s(e, "signature_b64").into();
        assert_eq!(
            String::from_utf8(st.artifact_jcs().unwrap()).unwrap(),
            s(e, "artifact_jcs_utf8"),
            "{label}: canonical artifact diverged"
        );
        let carried: OperatorDomainBindingV1 = serde_json::from_value(case["statement"].clone())
            .unwrap_or_else(|e| panic!("{label}: the pinned statement does not parse: {e}"));
        assert_eq!(
            carried, st,
            "{label}: pinned statement differs from the rebuilt one"
        );
    }
}

/// Which of the contract's refusals this crate's checks make. The others are
/// the callers' and must pass here.
fn refused_here(rule: Option<&str>) -> Option<bool> {
    match rule {
        // The member set: refused by the type before any check runs.
        Some("4-members") => None,
        Some(
            "4-values"
            | "5-host-name"
            | "6-operator-id"
            | "7.1-order"
            | "7.1-bind-max-validity"
            | "7.1-future"
            | "7.2-sequence",
        ) => Some(true),
        None | Some("5-public-suffix" | "6-signature" | "7.1-expired") => Some(false),
        Some(other) => panic!("rule {other:?} is not classified in this test"),
    }
}

#[test]
fn statement_validity_follows_the_contract() {
    let Some(dir) = family_dir() else { return };
    let v = load(&dir, "vectors.json");
    for case in v["statement_validity"]["cases"].as_array().expect("cases") {
        let label = s(case, "label");
        let rule = case["expected"]["rule"].as_str();
        let now = instant(case, "now");
        let parsed =
            serde_json::from_str::<OperatorDomainBindingV1>(s(case, "statement_json_utf8"));
        match refused_here(rule) {
            None => assert!(
                parsed.is_err(),
                "{label}: the member set breaks {rule:?} and the type accepted it"
            ),
            Some(refused) => {
                let st = parsed.unwrap_or_else(|e| panic!("{label}: does not parse: {e}"));
                let r = st.validate_structure(now);
                assert_eq!(
                    r.is_err(),
                    refused,
                    "{label}: rule {rule:?}, validate_structure returned {r:?}"
                );
                if rule == Some("7.1-expired") {
                    // The window at `now` is the caller's check; the statement is
                    // past it.
                    assert!(parse_instant("valid_until", &st.valid_until).unwrap() <= now);
                }
            }
        }
    }
}

#[test]
fn host_names_follow_the_contract() {
    let Some(dir) = family_dir() else { return };
    let h = &load(&dir, "vectors.json")["host_names"];
    for case in h["input_cases"].as_array().expect("input cases") {
        let label = s(case, "label");
        let got = normalize_domain(s(case, "input")).ok();
        assert_eq!(
            got.as_deref(),
            case["expected"]["domain_ascii"].as_str(),
            "input {label}"
        );
    }
    for case in h["carried_cases"].as_array().expect("carried cases") {
        let label = s(case, "label");
        let rule = case["expected"]["rule"].as_str();
        // The ICANN Public Suffix List rule is the consumer's (it needs the list);
        // every other host-name rule is enforced here.
        let refused = rule == Some("5-host-name");
        assert_eq!(
            validate_domain_ascii(s(case, "domain_ascii")).is_err(),
            refused,
            "carried {label} ({rule:?})"
        );
    }
    let np = &h["non_public_top_level_names"];
    for name in np["names"].as_array().expect("names") {
        let host = s(np, "template").replace("{name}", name.as_str().unwrap());
        assert!(
            normalize_domain(&host).is_err(),
            "input {host:?} must be refused"
        );
        assert!(
            validate_domain_ascii(&host).is_err(),
            "carried {host:?} must be refused"
        );
    }
}

/// What the published resource's type and limits accept. Matching needs the
/// signature, so it is held in the callers' tests.
#[test]
fn published_document_limits_follow_the_contract() {
    let Some(dir) = family_dir() else { return };
    let d = load(&dir, "documents.json");
    let mut bodies: std::collections::HashMap<String, Vec<u8>> = Default::default();
    for case in d["cases"].as_array().expect("cases") {
        let label = s(case, "label");
        let body = match case.get("body_construction") {
            Some(bc) => {
                let mut b = bodies[s(bc, "from_case")].clone();
                b.resize(
                    bc["append_spaces_to_total_bytes"].as_u64().unwrap() as usize,
                    b' ',
                );
                b
            }
            None => s(case, "body_utf8").as_bytes().to_vec(),
        };
        bodies.insert(label.to_string(), body.clone());
        let accepted = body.len() <= WELL_KNOWN_MAX_BYTES
            && serde_json::from_slice::<WellKnownBindings>(&body)
                .is_ok_and(|doc| (1..=WELL_KNOWN_MAX_ENTRIES).contains(&doc.bindings.len()));
        assert_eq!(
            accepted,
            case["expected"]["document_accepted"].as_bool().unwrap(),
            "document {label} ({:?})",
            case["expected"]["document_rule"]
        );
    }
}
