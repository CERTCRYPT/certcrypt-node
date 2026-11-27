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

//! The node's side of `operator.domain-binding/1`, against the contract's
//! `operator-domain-binding` family.
//!
//! The node is the producer: it derives its operator key from a seed, signs
//! statements with it and writes the document its host publishes at
//! `/.well-known/certcrypt-node.json`. This file holds it to the contract in
//! three ways:
//!
//! - the key a contract seed derives, and the contract's signatures verifying
//!   under it — and the tampered and mis-domained ones not verifying;
//! - every statement-validity case, checked the way a consumer checks it with
//!   the protocol core and ML-DSA-65 (the Public Suffix List rule excepted: it
//!   is the issuance service's, which holds the list);
//! - the document the node writes for its first bind: the signed payload
//!   byte-identical to the contract's `first-bind`, its signature valid, and the
//!   document acceptable and matching under the contract's own rules — the same
//!   rules the document cases pin.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use capacity_artifacts::operator_domain_binding::{
    parse_instant, OperatorDomainBindingV1, WellKnownBindings, INTENT_BIND, WELL_KNOWN_MAX_BYTES,
    WELL_KNOWN_MAX_ENTRIES,
};
use certcrypt_node::domain_binding::{
    DomainBinder, DomainBindingConfig, Publication, Registrar, Registration,
};
use certcrypt_node_core::operator_receipt::OperatorIdentity;
use chrono::{DateTime, Utc};
use serde_json::Value;

const ENV_FIXTURES_DIR: &str = "CERTCRYPT_CONFORMANCE_FIXTURES_DIR";
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

fn load(dir: &Path, name: &str) -> Value {
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

fn instant(v: &Value, key: &str) -> DateTime<Utc> {
    s(v, key).parse().expect("an RFC 3339 instant")
}

fn verifies(st: &OperatorDomainBindingV1) -> bool {
    let (Ok(pk), Ok(sig), Ok(msg)) = (
        B64.decode(&st.operator_public_key),
        B64.decode(&st.signature_b64),
        st.signing_message(),
    ) else {
        return false;
    };
    capacity_verify::mldsa::verify_detached(&pk, &sig, &msg).is_ok()
}

/// A consumer's stateless check of one parsed statement, without the Public
/// Suffix List rule: structure, signature under the carried key, window.
fn statement_ok(st: &OperatorDomainBindingV1, now: DateTime<Utc>) -> bool {
    st.validate_structure(now).is_ok()
        && verifies(st)
        && parse_instant("valid_until", &st.valid_until).is_ok_and(|until| until > now)
}

/// §8.1–§8.3 and §9 step 2: the acceptable document's matching statement.
fn evaluate(
    body: &[u8],
    host: &str,
    operator_id: &str,
    now: DateTime<Utc>,
) -> (bool, Option<String>) {
    if body.len() > WELL_KNOWN_MAX_BYTES {
        return (false, None);
    }
    let Ok(doc) = serde_json::from_slice::<WellKnownBindings>(body) else {
        return (false, None);
    };
    if !(1..=WELL_KNOWN_MAX_ENTRIES).contains(&doc.bindings.len()) {
        return (false, None);
    }
    let found = doc.bindings.iter().find(|st| {
        st.domain_ascii == host
            && st.operator_id == operator_id
            && st.intent == INTENT_BIND
            && statement_ok(st, now)
    });
    (
        true,
        found.map(|st| hex::encode(st.statement_digest().unwrap())),
    )
}

fn key_pair(v: &Value, label: &str) -> (Vec<u8>, Vec<u8>) {
    let k = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["label"] == label)
        .unwrap_or_else(|| panic!("key {label}"));
    let seed = hex::decode(s(k, "seed_hex")).unwrap();
    let (pk, sk) = capacity_verify::mldsa::keypair_from_seed(&seed).expect("keypair from seed");
    assert_eq!(
        B64.encode(&pk),
        s(k, "public_key_b64"),
        "key {label} from its seed"
    );
    (pk, sk)
}

#[test]
fn contract_signatures_verify_and_tampered_ones_do_not() {
    let Some(dir) = family_dir() else { return };
    let v = load(&dir, "vectors.json");
    for case in v["construction"]["cases"].as_array().unwrap() {
        let label = s(case, "label");
        let (pk, _) = key_pair(&v, s(&case["inputs"], "operator_key"));
        let msg = s(&case["expected"], "signing_message_utf8").as_bytes();
        let sig = B64.decode(s(&case["expected"], "signature_b64")).unwrap();
        assert!(
            capacity_verify::mldsa::verify_detached(&pk, &sig, msg).is_ok(),
            "{label}: the contract's signature does not verify"
        );
        if let Some(t) = case.get("tampered") {
            let st: OperatorDomainBindingV1 =
                serde_json::from_value(t["statement"].clone()).unwrap();
            assert!(!verifies(&st), "{label}: the tampered statement verifies");
        }
    }
}

#[test]
fn statement_validity_follows_the_contract() {
    let Some(dir) = family_dir() else { return };
    let v = load(&dir, "vectors.json");
    for case in v["statement_validity"]["cases"].as_array().unwrap() {
        let label = s(case, "label");
        let rule = case["expected"]["rule"].as_str();
        let now = instant(case, "now");
        let accepted =
            serde_json::from_str::<OperatorDomainBindingV1>(s(case, "statement_json_utf8"))
                .is_ok_and(|st| statement_ok(&st, now));
        // The Public Suffix List rule is the consumer's; on the node's side such a
        // statement is otherwise valid.
        let expected =
            case["expected"]["accepted"].as_bool().unwrap() || rule == Some("5-public-suffix");
        assert_eq!(accepted, expected, "{label} ({rule:?})");
    }
}

#[test]
fn document_cases_follow_the_contract() {
    let Some(dir) = family_dir() else { return };
    let d = load(&dir, "documents.json");
    let mut bodies: std::collections::HashMap<String, Vec<u8>> = Default::default();
    for case in d["cases"].as_array().unwrap() {
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
        let (accepted, matched) = evaluate(
            &body,
            s(case, "host"),
            s(case, "operator_id"),
            instant(case, "now"),
        );
        let e = &case["expected"];
        assert_eq!(
            accepted,
            e["document_accepted"].as_bool().unwrap(),
            "{label}: acceptance"
        );
        assert_eq!(
            matched.as_deref(),
            e["matching_statement_digest_hex"].as_str(),
            "{label}: matching statement"
        );
    }
}

/// Registers nothing: the node writes its document whatever the service says.
struct Offline;

impl Registrar for Offline {
    async fn register(&self, _body: Value) -> Registration {
        Registration::Unavailable("offline".into())
    }
    async fn check_published(&self, _d: &str, _s: &OperatorDomainBindingV1) -> Publication {
        Publication::Unreachable("offline".into())
    }
}

#[tokio::test]
async fn the_document_the_node_writes_matches_the_contract() {
    let Some(dir) = family_dir() else { return };
    let v = load(&dir, "vectors.json");
    let case = v["construction"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["label"] == "first-bind")
        .expect("first-bind");
    let i = &case["inputs"];
    let e = &case["expected"];
    let (pk, sk) = key_pair(&v, s(i, "operator_key"));
    let now = instant(i, "issued_at");

    let work = std::env::temp_dir().join(format!("cc-node-odb-conformance-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&work).unwrap();
    let cfg = DomainBindingConfig {
        domain: Some(s(i, "domain").into()),
        state_path: work.join("state.json"),
        published_path: work.join("certcrypt-node.json"),
        serve: false,
    };
    let binder = DomainBinder::new(
        cfg,
        Arc::new(OperatorIdentity::from_keypair(pk, sk)),
        None,
        Offline,
    );
    let report = binder.check(now, true).await.expect("a check pass");
    assert_eq!(
        report.signed,
        vec![1],
        "the first statement of a key is sequence 1"
    );

    let body = std::fs::read(work.join("certcrypt-node.json")).expect("the published document");
    let doc: WellKnownBindings = serde_json::from_slice(&body).expect("a well-known document");
    assert_eq!(doc.bindings.len(), 1);
    let st = &doc.bindings[0];
    assert_eq!(
        String::from_utf8(st.signed_payload_jcs().unwrap()).unwrap(),
        s(e, "signed_payload_jcs_utf8"),
        "the node's first bind diverges from the contract's signed payload"
    );
    assert_eq!(
        hex::encode(st.statement_digest().unwrap()),
        s(e, "statement_digest_hex")
    );
    assert!(verifies(st), "the node's signature does not verify");

    let host = s(e, "domain_ascii");
    let (accepted, matched) = evaluate(&body, host, s(e, "operator_id"), now);
    assert!(
        accepted,
        "the node's document is not acceptable under the contract's rules"
    );
    assert_eq!(matched.as_deref(), Some(s(e, "statement_digest_hex")));
    let _ = std::fs::remove_dir_all(&work);
}
