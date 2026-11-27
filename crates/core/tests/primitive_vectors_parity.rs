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

//! Parity against the conformance primitive byte-contract vectors
//! (`certcrypt-conformance/fixtures/primitives/`).
//!
//! These pin the byte-level contract of the zero-data profile primitives
//! (pseudonym derivation, operation-key Merkle tree) that
//! `certcrypt-verifier-toolkit-*` must reproduce in any language. This crate
//! must reproduce them too; this test guards against drift here. If a future edit changes the framing, the
//! leaf-hash rule, or the Merkle rule, the vector breaks loudly.

use capacity_verify::capacity_evidence::{
    operation_key_leaf_hash, OperationKeyDisclosure, ProjectedCommitment,
};
use certcrypt_node_core::merkle::{compute_merkle_root, verify_inclusion_proof};
use certcrypt_node_core::{derive_pseudonym as derive, Domain};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;

/// Environment variable that points at a `fixtures/primitives` directory.
///
/// Set it when the conformance suite is not a sibling checkout — a vendored
/// copy, a CI cache, a release tarball. It takes precedence over the sibling
/// path so a deliberate location always wins over a guess.
const ENV_PRIMITIVES_DIR: &str = "CERTCRYPT_CONFORMANCE_PRIMITIVES_DIR";

/// Opt-out for the one case where the suite genuinely cannot be present.
///
/// Set it to `1` and the parity tests skip loudly instead of failing. It exists
/// for a contributor who is building this crate alone and knows it — never for
/// CI, and never as a default.
const ENV_ALLOW_MISSING: &str = "CERTCRYPT_ALLOW_MISSING_CONFORMANCE";

/// The conformance contract version this repository is held to.
///
/// A gate that only requires the contract to be PRESENT lets two
/// implementations build green against DIFFERENT versions of it and diverge
/// anyway. What keeps implementations in step is agreeing on the same
/// `VERSION`, so a checkout that is not this one fails. Raising this constant
/// is the deliberate act of adopting a new contract.
const EXPECTED_VERSION: &str = "1.0.0";

/// Skip the version equality check while still requiring the contract, for the
/// one legitimate case: running against a newer suite to see what a bump would
/// break, before adopting it.
const ENV_ALLOW_VERSION_MISMATCH: &str = "CERTCRYPT_ALLOW_CONFORMANCE_VERSION_MISMATCH";

/// The checkout's `VERSION` must be the one this repo claims conformance
/// against.
///
/// `dir` may be the suite's `fixtures/` or a directory inside it, so walk up
/// until `VERSION` appears rather than assuming a fixed depth — assuming one
/// would report a missing VERSION instead of a wrong parent.
fn assert_contract_version(dir: &std::path::Path) {
    let mut root = dir;
    while !root.join("VERSION").is_file() {
        match root.parent() {
            // Stop at the conformance repo; never walk out into the filesystem
            // and pick up an unrelated VERSION from some ancestor directory.
            Some(p) if p.file_name().is_some() && root.file_name().is_some() => root = p,
            _ => break,
        }
        if root
            .file_name()
            .map(|n| n == "certcrypt-conformance")
            .unwrap_or(false)
            && !root.join("VERSION").is_file()
        {
            break;
        }
    }
    let path = root.join("VERSION");
    let Ok(found) = std::fs::read_to_string(&path) else {
        panic!(
            "conformance checkout at {} has no VERSION file — cannot confirm which contract \
             this run was held to",
            root.display()
        );
    };
    let found = found.trim();
    if found == EXPECTED_VERSION {
        return;
    }
    if std::env::var(ENV_ALLOW_VERSION_MISMATCH).as_deref() == Ok("1") {
        eprintln!(
            "WARNING: conformance contract is {found}, this repo claims {EXPECTED_VERSION}, and \
             {ENV_ALLOW_VERSION_MISMATCH}=1 — this run does NOT back a conformance claim"
        );
        return;
    }
    panic!(
        "conformance contract version mismatch: the checkout is {found}, this repo is held to \
         {EXPECTED_VERSION}.\n\
         Two implementations that each build green against a DIFFERENT contract version have no \
         agreement between them — which is the divergence the suite exists to prevent. Either \
         check out {EXPECTED_VERSION}, or adopt {found} by raising EXPECTED_VERSION and \
         re-running. Set {ENV_ALLOW_VERSION_MISMATCH}=1 to explore a bump without adopting it."
    );
}

/// Locate the conformance `fixtures/primitives` directory, or FAIL.
///
/// It never returns "not found" for a test to skip: a clone without the suite
/// alongside would run zero parity checks and report success, leaving the
/// contract unenforced exactly where nobody is watching. A missing contract is
/// not a passing test.
///
/// Resolution order — an explicit location, then the sibling checkout:
///   1. `$CERTCRYPT_CONFORMANCE_PRIMITIVES_DIR`
///   2. `../certcrypt-conformance/fixtures/primitives`, relative to the repo root
///
/// Neither found → panic with both, unless [`ENV_ALLOW_MISSING`] is set.
fn conformance_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_PRIMITIVES_DIR) {
        let dir = PathBuf::from(dir);
        // An explicit pointer that is wrong is always an error: the caller said
        // where the suite is, so falling back to a guess would hide their typo.
        assert!(
            dir.is_dir(),
            "{ENV_PRIMITIVES_DIR} points at {} which is not a directory",
            dir.display()
        );
        assert_contract_version(&dir);
        return Some(dir);
    }

    // crates/core -> crate root is CARGO_MANIFEST_DIR; repo root is two up; the
    // conformance repo is a sibling of certcrypt-node.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sibling = manifest.join("../../../certcrypt-conformance/fixtures/primitives");
    if let Ok(dir) = sibling.canonicalize() {
        if dir.is_dir() {
            assert_contract_version(&dir);
            return Some(dir);
        }
    }

    if std::env::var(ENV_ALLOW_MISSING).as_deref() == Ok("1") {
        eprintln!(
            "WARNING: conformance suite not found and {ENV_ALLOW_MISSING}=1 — \
             byte-contract parity was NOT verified in this run"
        );
        return None;
    }

    panic!(
        "conformance primitive vectors not found: neither ${ENV_PRIMITIVES_DIR} nor a sibling \
         certcrypt-conformance checkout ({}).\n\
         These vectors are the cross-language byte contract; skipping them silently is how a \
         divergence ships. Clone certcrypt-conformance alongside this repo, point \
         ${ENV_PRIMITIVES_DIR} at its fixtures/primitives, or set {ENV_ALLOW_MISSING}=1 to \
         acknowledge running without the contract.",
        sibling.display()
    );
}

fn load(path: PathBuf) -> Value {
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn domain_of(tag: &str) -> Domain {
    match tag {
        "holder" => Domain::Holder,
        "pool" => Domain::Pool,
        "authorization" => Domain::Authorization,
        other => panic!("unknown domain tag in vector: {other}"),
    }
}

#[test]
fn pseudonym_vectors_match() {
    let Some(dir) = conformance_dir() else {
        // Only reachable with the explicit opt-out; conformance_dir() panics otherwise.
        return;
    };
    let v = load(dir.join("pseudonym/vectors.json"));
    let vectors = v["vectors"].as_array().expect("vectors array");
    let mut by_name = std::collections::HashMap::new();
    for vec in vectors {
        let salt = vec["operation_salt_utf8"].as_str().unwrap();
        let domain = domain_of(vec["domain"].as_str().unwrap());
        let id = vec["stable_id"].as_str().unwrap();
        let expected = vec["expected_pseudonym_hex"].as_str().unwrap();
        let got = derive(salt.as_bytes(), domain, id);
        assert_eq!(
            got,
            expected,
            "pseudonym vector '{}' diverged — framing or KDF drifted",
            vec["name"].as_str().unwrap_or("?")
        );
        by_name.insert(vec["name"].as_str().unwrap().to_string(), got);
    }

    // The two load-bearing inequalities the vector file asserts.
    let salt1_holder = derive(b"operation-salt-1", Domain::Holder, "holder:example");
    let salt2_holder = derive(b"operation-salt-2", Domain::Holder, "holder:example");
    assert_ne!(salt1_holder, salt2_holder, "fresh salt must be unlinkable");

    let frame_a = derive(b"ab", Domain::Holder, "c");
    let frame_b = derive(b"a", Domain::Holder, "bc");
    assert_ne!(
        frame_a, frame_b,
        "length-framing must prevent boundary collision"
    );
}

#[test]
fn holder_keyset_vectors_match() {
    let Some(dir) = conformance_dir() else {
        // Only reachable with the explicit opt-out; conformance_dir() panics otherwise.
        return;
    };
    let v = load(dir.join("holder-keyset/vectors.json"));

    // Leaf hashes.
    let leaves_json = v["leaves"].as_array().unwrap();
    let mut leaf_hashes = Vec::new();
    for leaf in leaves_json {
        let pk = hex::decode(leaf["public_key_bytes_hex"].as_str().unwrap()).unwrap();
        let expected = leaf["expected_leaf_hash"].as_str().unwrap();
        let got = operation_key_leaf_hash(&pk);
        assert_eq!(
            got, expected,
            "leaf hash drifted at index {}",
            leaf["leaf_index"]
        );
        leaf_hashes.push(got);
    }

    // Root.
    let root = compute_merkle_root(&leaf_hashes);
    assert_eq!(root, v["expected_root"].as_str().unwrap(), "root drifted");

    // Inclusion proofs verify against the root.
    let tree_size = leaf_hashes.len();
    for proof_v in v["inclusion_proofs"].as_array().unwrap() {
        let idx = proof_v["leaf_index"].as_u64().unwrap() as usize;
        let siblings: Vec<String> = proof_v["sibling_hashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert!(
            verify_inclusion_proof(&leaf_hashes[idx], idx, &siblings, &root, tree_size),
            "inclusion proof for leaf {idx} does not verify against root"
        );
    }
}

#[test]
fn holder_keyset_trees_and_disclosure_cases_match() {
    let Some(dir) = conformance_dir() else {
        // Only reachable with the explicit opt-out; conformance_dir() panics otherwise.
        return;
    };
    let v = load(dir.join("holder-keyset/vectors.json"));

    // Every tree shape: root and every proof.
    for t in v["trees"].as_array().unwrap() {
        let n = t["tree_size"].as_u64().unwrap() as usize;
        let leaf_hashes: Vec<String> = t["public_keys_bytes_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| operation_key_leaf_hash(&hex::decode(h.as_str().unwrap()).unwrap()))
            .collect();
        let root = compute_merkle_root(&leaf_hashes);
        assert_eq!(
            root,
            t["expected_root"].as_str().unwrap(),
            "tree {n}: root drifted"
        );
        for p in t["inclusion_proofs"].as_array().unwrap() {
            let idx = p["leaf_index"].as_u64().unwrap() as usize;
            let siblings: Vec<String> = p["sibling_hashes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect();
            assert!(
                verify_inclusion_proof(&leaf_hashes[idx], idx, &siblings, &root, n),
                "tree {n}: leaf {idx} does not verify"
            );
        }
    }

    // Full disclosures: a disclosure that does not parse into the closed type
    // (an additional or missing member, an integer given as a string, a
    // fraction or a negative) is invalid; the rest go through the membership
    // check. The verdict must equal expected_valid.
    let cases = v["disclosure_cases"].as_array().unwrap();
    assert!(!cases.is_empty(), "disclosure cases present");
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let root = c["root"].as_str().unwrap();
        let got = serde_json::from_value::<OperationKeyDisclosure>(c["disclosure"].clone())
            .map(|d| d.verify_membership(root))
            .unwrap_or(false);
        assert_eq!(
            got,
            c["expected_valid"].as_bool().unwrap(),
            "disclosure case {name}"
        );
    }
}

#[test]
fn capacity_evidence_signing_bytes_match() {
    let Some(dir) = conformance_dir() else {
        // Only reachable with the explicit opt-out; conformance_dir() panics otherwise.
        return;
    };
    let v = load(dir.join("capacity-evidence/vectors.json"));
    let pc_json = &v["projected_commitment"];

    // Rebuild the projected commitment from the vector's fields.
    let pc: ProjectedCommitment = serde_json::from_value(pc_json.clone()).unwrap();
    let bytes = pc.signing_bytes();

    // The signing bytes must be exactly the pinned insertion-ordered JSON.
    let expected_utf8 = v["expected_signing_bytes_utf8"].as_str().unwrap();
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        expected_utf8,
        "projected commitment signing bytes diverged — JCS vs insertion-order, or field order drifted"
    );

    // And their digest must match.
    let digest = hex::encode(Sha3_256::digest(&bytes));
    assert_eq!(
        digest,
        v["expected_signing_bytes_digest"].as_str().unwrap(),
        "signing bytes digest drifted"
    );

    // Guard the load-bearing property explicitly: NOT JCS. In sorted-key JCS,
    // "authorization_pseudonym" would precede "commitment_version"; here it
    // must not.
    let pos_cv = expected_utf8.find("\"commitment_version\"").unwrap();
    let pos_ap = expected_utf8.find("\"authorization_pseudonym\"").unwrap();
    assert!(
        pos_cv < pos_ap,
        "signing bytes must be insertion-ordered (commitment_version before authorization_pseudonym), not JCS"
    );
}

// ─── field sets, constants and settlement preimages ────────────────────────
//
// The three tests above pin bytes node COMPUTES. The four below pin the parts
// of the contract that bytes cannot express: the field set of a signed
// preimage, the constants that decide admission, and the producer-side
// settlement preimages. They exist because a divergence in any of them leaves
// every digest correct — see each vector's `why_this_is_a_primitive`.

/// The settlement preimages node produces must hash to the pinned values, and
/// the two natural wrong canonicalizations must produce the pinned tripwires.
///
/// Pinning the tripwires is the point: reproducing the right digest proves
/// node's rule works, and reproducing the WRONG one proves the vector is
/// describing a real fork in the road rather than restating node's behavior.
#[test]
fn settlement_preimages_match_vectors() {
    let Some(dir) = conformance_dir() else {
        return;
    };
    let v = load(dir.join("settlement-preimages/vectors.json"));

    // --- leaf preimage ---
    let lp_v = &v["leaf_preimage"];
    let lp: certcrypt_node_core::settlement::LeafPreimage = leaf_preimage_from(&lp_v["preimage"]);
    let bytes = serde_json::to_vec(&lp).unwrap();
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        lp_v["expected_bytes_utf8"].as_str().unwrap(),
        "leaf preimage bytes diverged — insertion order or encoding drifted"
    );
    assert_eq!(
        certcrypt_node_core::merkle::compute_leaf_hash(&bytes),
        lp_v["expected_leaf_hash"].as_str().unwrap(),
        "leaf hash diverged from the vector"
    );
    // The wrong-canonicalization value the vector pins must be what node would
    // have produced had it reached for JCS. If this assert fails, the vector's
    // tripwire is stale and would no longer catch the mistake it names.
    let jcs = serde_jcs::to_vec(&lp).unwrap();
    assert_eq!(
        certcrypt_node_core::merkle::compute_leaf_hash(&jcs),
        lp_v["tripwire_if_jcs_used"].as_str().unwrap(),
        "the JCS tripwire no longer describes what JCS produces"
    );
    assert_eq!(
        hex::encode(Sha3_256::digest(&bytes)),
        lp_v["tripwire_if_domain_prefix_omitted"].as_str().unwrap(),
        "the no-prefix tripwire no longer describes what omitting 0x00 produces"
    );

    // --- batch-binding preimage ---
    let bb_v = &v["batch_binding_preimage"];
    let p = &bb_v["preimage"];
    let bbp = certcrypt_node_core::settlement::BatchBindingPreimage {
        v: p["v"].as_str().unwrap().to_string(),
        system_id: p["system_id"].as_str().unwrap().to_string(),
        rules_version: p["rules_version"].as_str().unwrap().to_string(),
        settlement_profile_id: p["settlement_profile_id"].as_str().unwrap().to_string(),
        batch_id: p["batch_id"].as_str().unwrap().to_string(),
        window_id: p["window_id"].as_str().unwrap().to_string(),
        leaf_count: p["leaf_count"].as_str().unwrap().to_string(),
        total_quantity: p["total_quantity"].as_str().unwrap().to_string(),
        settlement_root: p["settlement_root"].as_str().unwrap().to_string(),
    };
    let bb_bytes = serde_json::to_vec(&bbp).unwrap();
    assert_eq!(
        String::from_utf8(bb_bytes.clone()).unwrap(),
        bb_v["expected_bytes_utf8"].as_str().unwrap(),
        "batch-binding bytes diverged"
    );
    let digest = hex::encode(Sha3_256::digest(&bb_bytes));
    assert_eq!(
        digest,
        bb_v["expected_digest"].as_str().unwrap(),
        "batch-binding digest diverged"
    );
    assert_eq!(
        format!(
            "{}{digest}",
            certcrypt_node_core::settlement::SETTLEMENT_MEMO_PREFIX
        ),
        bb_v["expected_memo"].as_str().unwrap(),
        "memo diverged — prefix or digest"
    );
}

fn leaf_preimage_from(p: &Value) -> certcrypt_node_core::settlement::LeafPreimage {
    certcrypt_node_core::settlement::LeafPreimage {
        v: p["v"].as_str().unwrap().to_string(),
        system_id: p["system_id"].as_str().unwrap().to_string(),
        rules_version: p["rules_version"].as_str().unwrap().to_string(),
        settlement_profile_id: p["settlement_profile_id"].as_str().unwrap().to_string(),
        batch_id: p["batch_id"].as_str().unwrap().to_string(),
        leaf_index: p["leaf_index"].as_str().unwrap().to_string(),
        subtree_root: p["subtree_root"].as_str().unwrap().to_string(),
        cost_commitment: p["cost_commitment"].as_str().unwrap().to_string(),
        consumed_quantity: p["consumed_quantity"].as_str().unwrap().to_string(),
    }
}

/// Node's own types must carry EXACTLY the fields the shape vector declares.
///
/// Serializing and reading the keys back is the only way to ask a Rust struct
/// what it emits. A field node lacks, or one it adds, shows up here — and
/// nowhere else, because either way the digest node computes is correct for the
/// object node hashed.
#[test]
fn artifact_shape_matches_node_types() {
    let Some(dir) = conformance_dir() else {
        return;
    };
    let v = load(dir.join("artifact-shape/vectors.json"));
    let spec = |name: &str| -> Vec<String> {
        v["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["artifact"].as_str().unwrap() == name)
            .unwrap_or_else(|| panic!("shape vector has no artifact named {name}"))["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap().to_string())
            .collect()
    };
    // Compared as a SET, sorted on both sides. `serde_json::to_value` builds a
    // BTreeMap, so it cannot report insertion order — and it does not need to:
    // ORDER is pinned by the byte vectors (expected_bytes_utf8), which this file
    // checks in `settlement_preimages_match_vectors`. What only a set comparison
    // catches is a field present on one side and absent on the other.
    let keys_of = |val: &Value| -> Vec<String> {
        let mut k: Vec<String> = val
            .as_object()
            .expect("serialized artifact is an object")
            .keys()
            .cloned()
            .collect();
        k.sort();
        k
    };
    let sorted = |mut v: Vec<String>| -> Vec<String> {
        v.sort();
        v
    };

    // The settlement preimages, from the vector that carries their values.
    let sp = load(dir.join("settlement-preimages/vectors.json"));
    let lp = leaf_preimage_from(&sp["leaf_preimage"]["preimage"]);
    assert_eq!(
        keys_of(&serde_json::to_value(&lp).unwrap()),
        sorted(spec("settlement leaf preimage (ccab1-leaf)")),
        "LeafPreimage's fields differ from the contract — a field added or dropped here \
         changes the signed bytes while every digest stays internally correct"
    );

    let p = &sp["batch_binding_preimage"]["preimage"];
    let bbp = certcrypt_node_core::settlement::BatchBindingPreimage {
        v: p["v"].as_str().unwrap().to_string(),
        system_id: p["system_id"].as_str().unwrap().to_string(),
        rules_version: p["rules_version"].as_str().unwrap().to_string(),
        settlement_profile_id: p["settlement_profile_id"].as_str().unwrap().to_string(),
        batch_id: p["batch_id"].as_str().unwrap().to_string(),
        window_id: p["window_id"].as_str().unwrap().to_string(),
        leaf_count: p["leaf_count"].as_str().unwrap().to_string(),
        total_quantity: p["total_quantity"].as_str().unwrap().to_string(),
        settlement_root: p["settlement_root"].as_str().unwrap().to_string(),
    };
    assert_eq!(
        keys_of(&serde_json::to_value(&bbp).unwrap()),
        sorted(spec("settlement batch-binding preimage (ccab1)")),
        "BatchBindingPreimage's fields differ from the contract"
    );
}

/// The constants node compiles in must be the ones the contract pins.
///
/// These decide admission before a byte is hashed, so a divergence is not a
/// mislabel: node and the issuance service would disagree about whether a set is well-formed
/// at all.
#[test]
fn system_constants_match_the_contract() {
    let Some(dir) = conformance_dir() else {
        return;
    };
    let v = load(dir.join("submission-set-limits/vectors.json"));

    assert_eq!(
        capacity_artifacts::submission_set::MAX_SUBMISSION_SET_MEMBERS,
        v["member_cap"]["max_submission_set_members"]
            .as_u64()
            .unwrap() as usize,
        "node's member cap differs from the contract"
    );
    assert_eq!(
        certcrypt_node_core::settlement::SYSTEM_ID,
        v["system_constants"]["system_id"]["value"]
            .as_str()
            .unwrap(),
        "node's system_id differs from the contract — it sits inside signed preimages"
    );
}

/// The rules-domain table node resolves from must match the pinned one.
///
/// `settlement_profile_id` ends up inside the signed leaf preimage, so a
/// resolution that disagrees with the contract hashes the wrong substrate's
/// identifier into the leaf — with every digest still internally consistent.
#[test]
fn rules_domain_resolution_matches_vectors() {
    let Some(dir) = conformance_dir() else {
        return;
    };
    let v = load(dir.join("rules-domain/vectors.json"));

    for row in v["vectors"].as_array().unwrap() {
        let rules = row["rules_version"].as_str().unwrap();
        let got = capacity_artifacts::settlement::settlement_profile_for_rules(rules);
        match row["settlement_profile_id"].as_str() {
            Some(expected) => assert_eq!(
                got.unwrap_or_else(|| panic!("node does not resolve {rules}, the vector does")),
                expected,
                "settlement profile for {rules} diverged"
            ),
            // The vector pins that an unknown domain resolves to nothing. A node
            // that invents a fallback here would settle under a profile the
            // contract never assigned.
            None => assert!(
                got.is_none(),
                "node resolves {rules}, which the contract says is unknown — \
                 a fallback profile is never correct"
            ),
        }
        if let Some(ttl) = row["commitment_ttl_seconds"].as_u64() {
            assert_eq!(
                capacity_artifacts::settlement::commitment_ttl_seconds_for(rules),
                Some(ttl as u32),
                "commitment TTL for {rules} diverged"
            );
        }
    }
}

// ─── coverage: the gap cannot silently reopen ──────────────────────────────

/// The primitive families this crate's ROLE is held to.
///
/// This crate assembles submission sets and settlement material, so it sits on
/// the issuer/transport/settlement side of the role table in the conformance
/// README. It is not a verifier and returns no `VerifierResult`, so the verdict
/// fixtures and the verifier-only families do not apply.
const FAMILIES_IN_SCOPE: &[&str] = &[
    "artifact-shape",
    "capacity-evidence",
    "composite-m-prime",
    "composite-verification",
    "holder-keyset",
    "key-derivation",
    "level1-binding",
    "operator-receipt",
    "pseudonym",
    "rules-domain",
    "settlement-preimages",
    "submission-set-limits",
];

/// Families the contract carries that correctly do not apply here, each with the
/// reason. Kept beside [`FAMILIES_IN_SCOPE`] so the two together account for the
/// whole contract.
const OUT_OF_SCOPE: &[(&str, &str)] = &[
    (
        "ccvp-consistency",
        "verifier-side: resolving competing snapshots",
    ),
    (
        "collection-merkle",
        "the SDKs fold collections; this crate carries digests",
    ),
    (
        "independence-proof-signature",
        "the issuance service composes and signs the proof",
    ),
    (
        "key-derivation",
        "seed material belongs to the ceremony and the SDKs",
    ),
    (
        "manifest-resolution",
        "node resolves through capacity-verify's own resolver",
    ),
    (
        "original-material",
        "subject material belongs to the issuer SDK",
    ),
    (
        "submission-set",
        "the id recompute is exercised by the node crate's flow tests",
    ),
    (
        "strict-json",
        "subject material and certificates are parsed by the issuer SDK and the verifier; this crate carries digests",
    ),
    (
        "subject-ai-decision",
        "subject canonicalization belongs to the issuer SDK",
    ),
    (
        "subject-binary",
        "subject canonicalization belongs to the issuer SDK",
    ),
    (
        "subject-collection",
        "subject canonicalization belongs to the issuer SDK",
    ),
    (
        "subject-context-snapshot",
        "subject canonicalization belongs to the issuer SDK",
    ),
    (
        "subject-email",
        "subject canonicalization belongs to the issuer SDK",
    ),
    (
        "subject-text",
        "subject canonicalization belongs to the issuer SDK",
    ),
    ("verification-package", "assembled by the issuance service"),
    (
        "issuer-key-derivation",
        "issuer-side: the issuer derives its signing key from a seed the node never holds",
    ),
    (
        "ecdsa-p256-deterministic",
        "issuer-side: the node relays and verifies issuer signatures and signs nothing with \
         ECDSA P-256 (its receipts and possession proofs are ML-DSA-65)",
    ),
    (
        "operator-domain-binding",
        "the statement's bytes are capacity-artifacts' and the node crate signs and publishes it; \
         both are held to the family in their own operator-domain-binding conformance tests",
    ),
];

/// Every family this crate claims to cover must exist in the contract.
///
/// Guards the direction the coverage test cannot: a family renamed upstream would
/// otherwise leave a dead entry in the list, and the claim would keep passing
/// while covering one family less than it says.
#[test]
fn every_claimed_family_exists_in_the_contract() {
    let Some(dir) = conformance_dir() else {
        return;
    };
    for family in FAMILIES_IN_SCOPE {
        assert!(
            dir.join(family).join("vectors.json").is_file(),
            "this crate claims to cover '{family}', which the contract does not have — \
             renamed or removed upstream, so the claim is now false"
        );
    }
}

/// Every family in scope must be READ by a test in this file.
///
/// This is what keeps the contract from quietly outgrowing its consumers: a
/// family added to the suite that no consumer reads fails nothing, because
/// nothing requires anyone to read it. Listing a family and never opening it
/// would be the same silence with a longer list, so the list is verified
/// against the source rather than trusted.
#[test]
fn every_family_in_scope_is_actually_read() {
    let src = include_str!("primitive_vectors_parity.rs");
    for family in FAMILIES_IN_SCOPE {
        // The literal a test passes to `load(dir.join(...))`. Searching the source
        // is crude, but it cannot be satisfied by an assertion that reads nothing —
        // which is exactly what a mocked-out coverage check would allow.
        let needle = format!("\"{family}/vectors.json\"");
        assert!(
            src.contains(&needle),
            "'{family}' is in scope for this crate but no test opens \
             {family}/vectors.json — the contract covers it and this crate does not"
        );
    }
}

/// A family the contract grows must be classified, not ignored.
///
/// Fails when the suite carries a family that is in neither list, so a new vector
/// cannot arrive unnoticed: someone has to look at it and say which side it falls
/// on. That decision is cheap; discovering six months later that nobody made it
/// is not.
#[test]
fn new_contract_families_force_a_decision() {
    let Some(dir) = conformance_dir() else {
        return;
    };
    let mut unclassified = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read the contract's primitives dir") {
        let entry = entry.expect("read a primitives entry");
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let known = FAMILIES_IN_SCOPE.contains(&name.as_str())
            || OUT_OF_SCOPE.iter().any(|(f, _)| *f == name);
        if !known {
            unclassified.push(name);
        }
    }
    unclassified.sort();
    assert!(
        unclassified.is_empty(),
        "the contract carries families this crate has not classified: {unclassified:?}.\n\
         Add each to FAMILIES_IN_SCOPE with a test that reads it, or to OUT_OF_SCOPE with \
         the reason it does not apply. A family nobody classifies is a family nobody checks."
    );
}

/// The operator receipt this crate signs must reproduce the contract's bytes, and
/// the contract's own receipt must verify under node's verifier.
///
/// Both directions on purpose. Reproducing the signing bytes proves node
/// canonicalizes the same view (JCS over the no-signature form — NOT the
/// insertion order the evidence and binding artifacts use). Verifying the
/// vector's signature proves node accepts what another implementation produced,
/// which is the half a producer-only check would miss.
///
/// The signature value itself is not compared: ML-DSA-65 signing may be
/// hedged, so two conforming signers of identical bytes can differ. What is deterministic — and
/// therefore what the contract pins — is the bytes and the id derivation.
#[test]
fn operator_receipt_vectors_match() {
    let Some(dir) = conformance_dir() else {
        return;
    };
    let v = load(dir.join("operator-receipt/vectors.json"));

    for vec in v["vectors"].as_array().expect("vectors array") {
        let label = vec["label"].as_str().unwrap_or("?");
        let receipt: certcrypt_node_core::operator_receipt::OperatorReceipt =
            serde_json::from_value(vec["receipt"].clone())
                .unwrap_or_else(|e| panic!("receipt '{label}' does not fit node's type: {e}"));

        // The operator id must DERIVE from the published key. A receipt whose
        // signature checks out under an unrelated key would otherwise pass as
        // this operator.
        let pk = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            vec["operator_public_key_b64"]
                .as_str()
                .expect("operator key"),
        )
        .expect("operator key is base64");
        assert_eq!(
            certcrypt_node_core::operator_receipt::derive_operator_id(&pk),
            receipt.operator_id,
            "receipt '{label}': operator_id does not derive from the published key"
        );

        // The no-signature signing view, canonicalized. JCS here, insertion order
        // elsewhere — neither can be guessed from the other, which is why each
        // artifact pins its own.
        let view = serde_json::json!({
            "receipt_version": receipt.receipt_version,
            "operator_id": receipt.operator_id,
            "submission_set_id": receipt.submission_set_id,
            "system_id": receipt.system_id,
            "rules_version": receipt.rules_version,
            "issued_at": receipt.issued_at,
        });
        let canon = serde_jcs::to_vec(&view).expect("jcs the receipt view");
        assert_eq!(
            String::from_utf8(canon.clone()).unwrap(),
            vec["expected_signing_bytes_utf8"].as_str().unwrap(),
            "receipt '{label}': signing bytes diverged — JCS vs insertion order, or field set"
        );
        assert_eq!(
            hex::encode(Sha3_256::digest(&canon)),
            vec["expected_signing_bytes_digest"].as_str().unwrap(),
            "receipt '{label}': signing-bytes digest diverged"
        );

        // And node must ACCEPT the contract's own receipt.
        receipt.verify_signature(&pk).unwrap_or_else(|e| {
            panic!("receipt '{label}': node rejects a receipt the contract pins as valid: {e}")
        });
    }
}

/// One custodied seed must materialize the whole composite identity exactly as
/// the contract pins it: the P-256 half, the ML-DSA-65 half, and the fingerprint
/// over both.
///
/// This is the root of every signature node produces. A divergence here is not a
/// wrong digest somewhere downstream — it is a different IDENTITY, signing
/// artifacts that resolve to a key no other implementation derives from the same
/// seed. Nothing later can detect that, because everything later is internally
/// consistent with the wrong key.
#[test]
fn key_derivation_vectors_match() {
    let Some(dir) = conformance_dir() else {
        return;
    };
    let v = load(dir.join("key-derivation/vectors.json"));

    for vec in v["vectors"].as_array().expect("vectors array") {
        let label = vec["label"].as_str().unwrap_or("?");
        let seed: [u8; 32] = hex::decode(vec["seed_hex"].as_str().expect("seed_hex"))
            .expect("seed is hex")
            .try_into()
            .expect("seed is 32 bytes");

        // Classical half: HKDF-SHA3-256 with its own info string, then SEC1.
        let sk = capacity_verify::ecdsa_p256::signing_key_from_seed(&seed);
        let uncompressed = capacity_verify::ecdsa_p256::public_key_sec1(&sk, false);
        assert_eq!(
            hex::encode(&uncompressed),
            vec["p256_public_key_sec1_uncompressed_hex"]
                .as_str()
                .unwrap(),
            "key-derivation '{label}': P-256 uncompressed SEC1 diverged — HKDF info string, \
             oversampling, or the mod-n reduction"
        );
        // Both encodings are pinned because they are different byte strings, and
        // the fingerprint below depends on which one you feed it.
        assert_eq!(
            hex::encode(capacity_verify::ecdsa_p256::public_key_sec1(&sk, true)),
            vec["p256_public_key_sec1_compressed_hex"].as_str().unwrap(),
            "key-derivation '{label}': P-256 compressed SEC1 diverged"
        );

        // Post-quantum half: the seed IS the FIPS 204 input, no KDF.
        let (mldsa_pk, _sk) =
            capacity_verify::mldsa::keypair_from_seed(&seed).expect("ML-DSA keypair from seed");
        assert_eq!(
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &mldsa_pk),
            vec["mldsa65_public_key_b64"].as_str().unwrap(),
            "key-derivation '{label}': ML-DSA-65 public key diverged — the seed must be used \
             verbatim as xi, with no domain separation"
        );

        // The fingerprint an implementation must RECOMPUTE rather than trust:
        // classical component first, uncompressed. Feeding it the compressed form
        // yields a different value, which is why both are pinned above.
        let mut preimage = uncompressed.clone();
        preimage.extend_from_slice(&mldsa_pk);
        assert_eq!(
            hex::encode(Sha3_256::digest(&preimage)),
            vec["composite_root_fingerprint"].as_str().unwrap(),
            "key-derivation '{label}': composite fingerprint diverged — component order, or \
             the compressed SEC1 form used where the uncompressed one belongs"
        );
    }
}

/// The Level-1 binding's signed bytes are insertion-ordered, not JCS.
///
/// Node verifies issuer authentication against these bytes, so reconstructing
/// them differently means rejecting bindings the system domain actually signed —
/// and the two canonicalizations coexist in this system, which makes JCS the
/// natural wrong guess. The vector pins the digest JCS WOULD have produced, and
/// this test reproduces it too: the tripwire only works if it still describes
/// what the mistake actually yields.
#[test]
fn level1_binding_vectors_match() {
    let Some(dir) = conformance_dir() else {
        return;
    };
    let v = load(dir.join("level1-binding/vectors.json"));

    for vec in v["vectors"].as_array().expect("vectors array") {
        let label = vec["label"].as_str().unwrap_or("?");
        let b = &vec["binding"];
        let binding =
            capacity_artifacts::capacity_holder_authorization::Level1AuthorizationBinding {
                system_id: b["system_id"].as_str().unwrap().to_string(),
                rules_version: b["rules_version"].as_str().unwrap().to_string(),
                system_root_fingerprint: b["system_root_fingerprint"].as_str().unwrap().to_string(),
                authorized_role: b["authorized_role"].as_str().unwrap().to_string(),
                authorization_issuer_kid: b["authorization_issuer_kid"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                valid_from: b["valid_from"].as_str().unwrap().to_string(),
                valid_until: b["valid_until"].as_str().unwrap().to_string(),
                holder_key_set_root: b["holder_key_set_root"].as_str().unwrap().to_string(),
            };

        let bytes = binding.signing_bytes().expect("binding signing bytes");
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            vec["expected_signing_bytes_utf8"].as_str().unwrap(),
            "level1-binding '{label}': signing bytes diverged — field order or encoding"
        );
        assert_eq!(
            hex::encode(Sha3_256::digest(&bytes)),
            vec["expected_signing_bytes_digest"].as_str().unwrap(),
            "level1-binding '{label}': signing-bytes digest diverged"
        );

        // The tripwire must still describe what JCS produces. If this fails, the
        // vector's warning has gone stale and would no longer catch the mistake.
        let jcs = serde_jcs::to_vec(&binding).expect("jcs the binding");
        assert_eq!(
            hex::encode(Sha3_256::digest(&jcs)),
            vec["expected_digest_if_jcs_wrongly_applied"]
                .as_str()
                .unwrap(),
            "level1-binding '{label}': the JCS tripwire no longer describes what JCS yields"
        );
    }
}

/// The composite M′ framing: the last deterministic step before signing.
///
/// A composite signature cannot be pinned as bytes — an ECDSA nonce and a
/// hedged ML-DSA signature can differ between signers — so this is where the byte contract has to
/// stop. It is also where a divergence does the most damage: two implementations
/// that frame M′ differently each verify their OWN signatures perfectly and
/// neither verifies the other's. Every local test passes on both sides, and
/// nothing fails until they meet.
#[test]
fn composite_m_prime_vectors_match() {
    let Some(dir) = conformance_dir() else {
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
        assert_eq!(
            hex::encode(Sha3_256::digest(&m)),
            vec["expected_m_prime_sha3_256"].as_str().unwrap(),
            "composite-m-prime '{label}': digest of M′ diverged"
        );
    }

    // The property the profile is in the framing FOR: the same payload digest
    // under a different profile must not produce the same M′, or a signature
    // could be reinterpreted under a profile it was never made for.
    let a = capacity_verify::composite::composite_m_prime("p256-mldsa65/1", &"a".repeat(64));
    let b = capacity_verify::composite::composite_m_prime("p256-mldsa65/2", &"a".repeat(64));
    assert_ne!(
        a, b,
        "the composite profile must change M′ — omitting it from the framing makes a \
         signature reinterpretable across profiles"
    );
}

/// What node REFUSES when verifying a composite signature.
///
/// The companion to [`composite_m_prime_vectors_match`]: that one fixes the
/// message, this one fixes the decisions taken around it. A valid signature
/// proves the math works and says nothing about what the code does with an
/// invalid one — and the refusals here are policy the code enforces, not
/// properties the cryptography provides.
///
/// The load-bearing case is `missing-mldsa-component`: its classical half
/// verifies perfectly, so an implementation treating the post-quantum floor as
/// optional accepts it while every cryptographic check it runs passes. Node and
/// the verifier disagreeing there means disagreeing about which certificates
/// exist, with no positive test on either side noticing.
#[test]
fn composite_verification_vectors_match() {
    let Some(dir) = conformance_dir() else {
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
    for case in v["cases"].as_array().expect("cases array") {
        let label = case["label"].as_str().unwrap_or("?");
        let expected_alg = case["expected_composite_alg_id"]
            .as_str()
            .expect("expected alg");
        // The composite object has exactly alg, mode and signatures, and the wire
        // type refuses unknown component members: a signature of any other shape
        // does not parse, which is a refusal.
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
            // Rebuilt per case: the borrow struct is not Copy, and a fresh one
            // keeps each case independent of the last.
            Some(sig) => capacity_verify::composite::verify_composite(
                expected_alg,
                digest,
                sig,
                capacity_verify::composite::CompositePublicKeys {
                    classical_pub: &classical,
                    mldsa_pub: &mldsa_pub,
                },
            )
            .map_err(|e| e.to_string()),
            None => {
                Err("signature does not have the shape of the composite wire object".to_string())
            }
        };
        match case["expected_outcome"].as_str().expect("expected_outcome") {
            "accepted" => got.unwrap_or_else(|e| {
                panic!("case '{label}': node rejects a composite the contract pins as valid: {e}")
            }),
            "rejected" => assert!(
                got.is_err(),
                "case '{label}': node ACCEPTS a composite the contract refuses — {}",
                case["why"].as_str().unwrap_or("")
            ),
            other => panic!("case '{label}': unknown expected_outcome {other}"),
        }
    }
}
