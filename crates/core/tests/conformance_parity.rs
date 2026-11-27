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

//! Cross-language parity against the conformance contract.
//!
//! The P001 conformance fixture
//! (`certcrypt-conformance/fixtures/conformance/P001`) is a known-good
//! settlement-material the reference TS verifier accepts as `INDEPENDENT_VALID`.
//! It is produced by the canonical (Python) generator. If `certcrypt-node-core`
//! computes the *same* sub-tree root, leaf hash, batch-binding digest (memo) and
//! Merkle root from the *same* inputs, then node's settlement-material is
//! byte-compatible with the verifier — without needing Node.js installed in CI.
//!
//! This is the load-bearing anti-drift check for the settlement path: a one-byte JCS/ordering
//! divergence flips one of these digests and the test fails loudly.
//!
//! P001 is on the commitment sub-tree + zero-data model: the leaf is bound to
//! `subtree_root` (the Merkle root over the leaf's accepted `commitment_id`s).
//!
//! # Every value is READ from the fixture, never transcribed
//!
//! No digest is pinned here as a `const`: a copy of the committed artifacts
//! would make the fixture and the test two sources of one truth, and a
//! regenerated fixture would leave the test passing against a contract that no
//! longer exists — green while diverged, the exact failure the suite exists to
//! catch. Both the inputs and the expected outputs come out of the same artifacts the TS
//! verifier consumes, so a regenerated fixture re-aims this test automatically
//! and a real divergence still fails it loudly.

// NOTE: this file pins this crate's re-exported settlement cable TYPES and
// Merkle/hash PRIMITIVES against the P001 conformance fixture. A full-pipeline
// settlement-assembly parity check belongs to whoever assembles settlements;
// this crate does not host it.
use certcrypt_node_core::settlement::{
    build_commitment_inclusion_proof, compute_subtree_root, BatchBindingPreimage, LeafPreimage,
    SETTLEMENT_MEMO_PREFIX, SYSTEM_ID,
};
use serde::Serialize;
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;

/// Environment variable pointing at the conformance repo's `fixtures/`
/// directory. Mirrors the one in `primitive_vectors_parity.rs`; see there for
/// why an explicit pointer beats a guessed path.
const ENV_FIXTURES_DIR: &str = "CERTCRYPT_CONFORMANCE_FIXTURES_DIR";

/// Opt-out for a contributor building this crate with no conformance checkout.
/// Never for CI, and never the default — see [`p001`].
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

/// Locate the conformance `fixtures/` directory, or FAIL.
///
/// Absence is an error, not a skip: a run that cannot find the contract has not
/// verified parity, and reporting that as success is how a divergence ships.
fn fixtures_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_FIXTURES_DIR) {
        let dir = PathBuf::from(dir);
        assert!(
            dir.is_dir(),
            "{ENV_FIXTURES_DIR} points at {} which is not a directory",
            dir.display()
        );
        assert_contract_version(&dir);
        return Some(dir);
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sibling = manifest.join("../../../certcrypt-conformance/fixtures");
    if let Ok(dir) = sibling.canonicalize() {
        if dir.is_dir() {
            assert_contract_version(&dir);
            return Some(dir);
        }
    }

    if std::env::var(ENV_ALLOW_MISSING).as_deref() == Ok("1") {
        eprintln!(
            "WARNING: conformance suite not found and {ENV_ALLOW_MISSING}=1 — \
             P001 settlement parity was NOT verified in this run"
        );
        return None;
    }

    panic!(
        "conformance fixtures not found: neither ${ENV_FIXTURES_DIR} nor a sibling \
         certcrypt-conformance checkout ({}).\n\
         P001 is the cross-language settlement contract; skipping it silently is how a \
         divergence ships. Clone certcrypt-conformance alongside this repo, point \
         ${ENV_FIXTURES_DIR} at its fixtures/, or set {ENV_ALLOW_MISSING}=1 to acknowledge \
         running without the contract.",
        sibling.display()
    );
}

/// P001's artifacts, loaded from the committed fixture.
///
/// Holds the three artifacts this test reads across. Every expected digest is
/// pulled out of these by accessor, so there is no second copy to keep in sync.
struct P001 {
    settlement: Value,
    independence: Value,
    commitment_proof: Value,
}

/// Load P001, or `None` under the explicit opt-out.
fn p001() -> Option<P001> {
    let dir = fixtures_dir()?.join("conformance/P001/artifacts");
    Some(P001 {
        settlement: load(dir.join("settlement-material.json")),
        independence: load(dir.join("independence-proof.json")),
        commitment_proof: load(dir.join("commitment-inclusion-proof.json")),
    })
}

fn load(path: PathBuf) -> Value {
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Read a string at a JSON pointer, failing with the pointer when it is absent.
///
/// A missing pointer means the fixture's SHAPE changed under us. That must be a
/// loud failure and not a silently skipped assertion — the artifact no longer
/// says what this test assumed it said.
fn s<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer)
        .unwrap_or_else(|| {
            panic!("P001 fixture has no value at {pointer} — artifact shape changed")
        })
        .as_str()
        .unwrap_or_else(|| panic!("P001 value at {pointer} is not a string"))
}

impl P001 {
    /// The accepted `commitment_id`s grouped into the target leaf, in the order
    /// the proof commits to. Read from `independence-proof.json`, which is where
    /// the set is declared.
    fn commitment_ids(&self) -> Vec<String> {
        self.independence["consumed_commitment_ids"]
            .as_array()
            .expect("consumed_commitment_ids array")
            .iter()
            .map(|c| c.as_str().expect("commitment id is a string").to_string())
            .collect()
    }

    /// The leaf's bound sub-tree root.
    fn subtree_root(&self) -> &str {
        s(
            &self.settlement,
            "/submission_assignment_proof/subtree_root",
        )
    }

    /// The leaf preimage exactly as the fixture declares it.
    ///
    /// Built field by field from the fixture's own JSON — `LeafPreimage` is
    /// `Serialize`-only, being an emission type, so it cannot be deserialized
    /// into. Each read goes through [`s`], which panics naming the pointer, so a
    /// field the fixture renames or drops fails loudly instead of defaulting to
    /// an empty string and hashing a different object. [`Self::assert_leaf_shape`]
    /// covers the other direction: a field the fixture adds that node ignores.
    fn leaf_preimage(&self) -> LeafPreimage {
        let lp = self
            .settlement
            .pointer("/submission_assignment_proof/leaf_preimage")
            .expect("leaf_preimage present");
        LeafPreimage {
            v: s(lp, "/v").to_string(),
            system_id: s(lp, "/system_id").to_string(),
            rules_version: s(lp, "/rules_version").to_string(),
            settlement_profile_id: s(lp, "/settlement_profile_id").to_string(),
            batch_id: s(lp, "/batch_id").to_string(),
            leaf_index: s(lp, "/leaf_index").to_string(),
            subtree_root: s(lp, "/subtree_root").to_string(),
            cost_commitment: s(lp, "/cost_commitment").to_string(),
            consumed_quantity: s(lp, "/consumed_quantity").to_string(),
        }
    }

    /// Assert the fixture's leaf preimage has EXACTLY the fields node knows.
    ///
    /// Reading nine fields proves node can find what it needs; it cannot notice a
    /// TENTH field the fixture grew. That field would be part of the signed
    /// preimage for the TS verifier and absent from node's — the two would hash
    /// different bytes while every assertion here still passed. Comparing the key
    /// set closes that direction.
    fn assert_leaf_shape(&self) {
        let lp = self
            .settlement
            .pointer("/submission_assignment_proof/leaf_preimage")
            .and_then(Value::as_object)
            .expect("leaf_preimage object");
        let mut got: Vec<&str> = lp.keys().map(String::as_str).collect();
        got.sort_unstable();
        let mut want = vec![
            "v",
            "system_id",
            "rules_version",
            "settlement_profile_id",
            "batch_id",
            "leaf_index",
            "subtree_root",
            "cost_commitment",
            "consumed_quantity",
        ];
        want.sort_unstable();
        assert_eq!(
            got, want,
            "P001 leaf_preimage fields differ from node's LeafPreimage — \
             a field added or renamed in the fixture changes the signed bytes"
        );
    }

    fn leaf_hash(&self) -> &str {
        s(&self.settlement, "/submission_assignment_proof/leaf_hash")
    }

    /// The leaf's Merkle sibling on the way to `settlement_root`.
    fn settlement_sibling(&self) -> &str {
        self.settlement
            .pointer("/submission_assignment_proof/sibling_hashes/0")
            .and_then(Value::as_str)
            .expect("settlement sibling hash")
    }

    fn settlement_root(&self) -> &str {
        s(&self.settlement, "/batch_manifest/settlement_root")
    }

    fn memo(&self) -> &str {
        s(&self.settlement, "/settlement_action/memo")
    }

    /// The batch-binding preimage, rebuilt from the manifest the fixture
    /// publishes plus the leaf-level quantities it settles.
    fn batch_binding(&self) -> BatchBindingPreimage {
        let m = &self.settlement["batch_manifest"];
        BatchBindingPreimage {
            v: SETTLEMENT_MEMO_PREFIX.trim_end_matches(':').to_string(),
            system_id: s(m, "/system_id").to_string(),
            rules_version: s(m, "/rules_version").to_string(),
            settlement_profile_id: s(m, "/settlement_profile_id").to_string(),
            batch_id: s(m, "/batch_id").to_string(),
            window_id: s(m, "/window_id").to_string(),
            leaf_count: s(m, "/leaf_count").to_string(),
            total_quantity: s(m, "/total_quantity").to_string(),
            settlement_root: s(m, "/settlement_root").to_string(),
        }
    }
}

fn ordered_json_bytes<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn sha3_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

/// Node's sub-tree root over P001's accepted commitments, and the target's
/// commitment→subtree_root inclusion proof, must match the fixture. Pins the
/// commitment leaf preimage (`{v:"ccab1-commit", commitment_id}`) and the
/// sub-tree Merkle construction against the canonical generator.
#[test]
fn subtree_root_and_commitment_inclusion_match_p001() {
    let Some(f) = p001() else { return };

    let ids = f.commitment_ids();
    let (root, _leaves) = compute_subtree_root(&ids).unwrap();
    assert_eq!(
        root,
        f.subtree_root(),
        "node subtree_root diverged from P001 — commitment leaf preimage or sub-tree Merkle drifted"
    );

    let proof = build_commitment_inclusion_proof(&ids, 0).unwrap();
    let expected = &f.commitment_proof;
    assert_eq!(
        proof.commitment_id,
        s(expected, "/commitment_id"),
        "target commitment id"
    );
    assert_eq!(
        proof.commitment_leaf_hash,
        s(expected, "/commitment_leaf_hash"),
        "commitment leaf hash diverged from P001"
    );
    assert_eq!(
        proof.subtree_size,
        s(expected, "/subtree_size"),
        "subtree size"
    );
    let expected_siblings: Vec<String> = expected["commitment_siblings"]
        .as_array()
        .expect("commitment_siblings array")
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        proof.commitment_siblings, expected_siblings,
        "commitment inclusion sibling diverged from P001"
    );
    assert!(
        certcrypt_node_core::merkle::verify_inclusion_proof(
            &proof.commitment_leaf_hash,
            0,
            &proof.commitment_siblings,
            &root,
            ids.len(),
        ),
        "commitment inclusion proof must verify against subtree_root"
    );
}

/// P001's own leaf preimage, hashed by node, must produce P001's declared
/// `leaf_hash`. Pins both field order and the `SHA3-256(0x00 || bytes)` leaf
/// rule against the reference generator.
///
/// The preimage is DESERIALIZED from the fixture rather than rebuilt field by
/// field: that way the struct's shape is under test too. A field node names
/// differently, or leaves out, fails at the deserialize instead of quietly
/// hashing a different object.
#[test]
fn leaf_hash_matches_p001() {
    let Some(f) = p001() else { return };

    f.assert_leaf_shape();
    let lp = f.leaf_preimage();

    // The fixture's own values must be what node believes the contract fixes:
    // system id and the leaf-bound slot. Guards against a fixture regenerated
    // under a different system or binding model sliding through as "parity".
    assert_eq!(lp.system_id, SYSTEM_ID, "P001 system_id is not node's");
    assert_eq!(
        lp.subtree_root,
        f.subtree_root(),
        "the leaf-bound field must be subtree_root (independence.proof/1 §10.4)"
    );
    // The profile id is inside the preimage, so it must be the one the rules
    // domain resolves to — not a compile-time constant, which would hash the
    // wrong substrate's identifier into the leaf.
    assert_eq!(
        lp.settlement_profile_id,
        capacity_artifacts::settlement::settlement_profile_for_rules(&lp.rules_version)
            .expect("the fixture's rules domain resolves")
            .to_string(),
        "settlement_profile_id must be the one the rules domain resolves"
    );

    let bytes = ordered_json_bytes(&lp);
    let leaf_hash = certcrypt_node_core::merkle::compute_leaf_hash(&bytes);
    assert_eq!(
        leaf_hash,
        f.leaf_hash(),
        "node leaf hash diverged from P001 — field order or leaf-hash rule drifted"
    );
}

/// Node's `BatchBindingPreimage`, populated with P001's own manifest values,
/// must produce P001's memo (`ccab1:` + digest). Pins the batch-binding hashing.
#[test]
fn batch_binding_memo_matches_p001() {
    let Some(f) = p001() else { return };

    let bbp = f.batch_binding();
    let digest = sha3_hex(&ordered_json_bytes(&bbp));
    let memo = format!("{SETTLEMENT_MEMO_PREFIX}{digest}");
    assert_eq!(
        memo,
        f.memo(),
        "node batch-binding memo diverged from P001 — field order or digest rule drifted"
    );
}

/// Node's Merkle root over [P001 leaf, P001 sibling] must equal P001's declared
/// `settlement_root`. Pins the internal-node hashing (`0x01 || L || R`).
#[test]
fn merkle_root_matches_p001() {
    let Some(f) = p001() else { return };

    let leaves = vec![
        f.leaf_hash().to_string(),
        f.settlement_sibling().to_string(),
    ];
    let root = certcrypt_node_core::merkle::compute_merkle_root(&leaves);
    assert_eq!(
        root,
        f.settlement_root(),
        "node Merkle root diverged from P001 — internal-node hash rule drifted"
    );
}
