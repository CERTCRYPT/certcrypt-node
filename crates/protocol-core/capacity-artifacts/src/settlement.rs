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

//! Settlement-material wire types + deterministic Merkle/hash primitives.
//!
//! These are the cable types the offline verifier consumes
//! (`certcrypt-verifier-toolkit-js/core/independent/settlement.ts`,
//! the aggregated settlement profile) plus the deterministic primitives that build
//! the leaf/sub-tree hashes and inclusion proofs. Every digest, the Merkle
//! root and the inclusion proof are computed **locally and deterministically** —
//! none of them need the chain.
//!
//! Producing settlement (submitting to the substrate and assembling the material)
//! belongs to the producer, not here: this crate carries only the shared wire
//! types and primitives, so every implementation that links it speaks the same
//! byte-exact format.
//!
//! ## Canonical JSON discipline
//!
//! The verifier hashes `LeafPreimage` and `BatchBindingPreimage` with an
//! **insertion-ordered** JSON serializer (`canonicalJsonBytes`), *not* RFC 8785
//! JCS (which sorts keys). We therefore serialize these two structs with plain
//! `serde_json` and declare their fields in the exact verifier order. Field
//! order in this file is load-bearing — do not reorder.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const SYSTEM_ID: &str = "certcrypt";
// Memo prefix is stable across environments (settlement memo format namespace).
//
// NOT substrate-specific: `ccab1:` is CERTCRYPT's own anchor namespace, it is what the offline
// verifier recomputes, and it is fixed by the conformance fixtures. It travels
// unchanged to any substrate that can carry ~70 bytes alongside a transaction
// (on XRPL it travels byte-identical in a transaction Memo).
pub const SETTLEMENT_MEMO_PREFIX: &str = "ccab1:";
// The asset symbol, stable across environments and substrates.
//
// `CERT` is the asset symbol on every substrate (it is `CERT` on the XRPL MPT
// too), but a contract account hosting it is something only some chains have:
// XRPL has no contract, only an issuer account. Both are asserted by the offline verifier
// and pinned by the fixtures; the wire fields they populate are substrate-neutral
// (`token_symbol`, `token_contract`).
pub const SETTLEMENT_TOKEN_SYMBOL: &str = "CERT";

/// The settlement profile a rules domain produces material under.
///
/// The rules domain selects the profile (`settlement-material/1` §6), and that
/// pairing is contract: it is published in the conformance suite
/// (`fixtures/primitives/rules-domain`) and every implementation resolves it the
/// same way. This function is the whole of it — no deployment configuration is
/// needed to answer the question, and none is consulted.
///
/// `None` for an unknown domain, and callers MUST fail closed on it: producing
/// material under a guessed profile puts the wrong identifier inside every
/// digest, and the identifier is part of what each digest commits to
/// (`settlement.binding/1` §5.1). A fallback would be worse than an error,
/// because the material it produced would look well-formed.
pub fn settlement_profile_for_rules(rules_version: &str) -> Option<&'static str> {
    match rules_version {
        "rules/2026-01" => Some(SETTLEMENT_PROFILE_AGGREGATED_XRPL),
        // The conformance domain describes no deployment of its own: it exercises
        // the PUBLISHED profile's shape against pinned vectors, so a third-party
        // verifier is tested against what it will actually meet.
        "rules/conformance" => Some(SETTLEMENT_PROFILE_AGGREGATED_XRPL),
        _ => None,
    }
}

/// The aggregated settlement profile every rules domain currently produces under.
///
/// Named rather than repeated: it travels inside the leaf and batch-binding
/// preimages, so it is part of what each digest commits to.
pub const SETTLEMENT_PROFILE_AGGREGATED_XRPL: &str = "settlement.aggregated.xrpl/1";

/// The capacity-commitment TTL, in seconds, for a `rules_version`.
///
/// Public rule of the rules-domain, not a per-issuer setting: the verifier
/// requires `expires_at == issued_at + ttl` (COMMITMENT_TTL_VALID) precisely so
/// an issuer cannot widen its own window. Mirrors `commitment_ttl_seconds` in the
/// verifier toolkit's per-environment config — the same public value, expressed
/// where the backend can enforce it at submit instead of leaving it to be
/// discovered at verification time.
///
/// `None` for a version this build does not know. Callers MUST treat that as a
/// refusal, never as "no limit": accepting an unbounded window is the exact
/// failure this function exists to prevent.
///
/// Only published domains are listed. A deployment running under a domain of its
/// own declares that domain's TTL in its own configuration and consults it after
/// this table, never instead of it — so no deployment can contradict a published
/// value.
pub const fn commitment_ttl_seconds_for(rules_version: &str) -> Option<u32> {
    match rules_version.as_bytes() {
        b"rules/2026-01" => Some(86_400),
        b"rules/conformance" => Some(2_592_000),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Wire types — serialize to the exact shape the verifier consumes.
//
// The leaf types also deserialize, so a Rust verifier can read material it did
// not produce (the conformance vectors) instead of only re-checking its own. The
// containers that carry them stay serialize-only: a verifier must see an ABSENT
// member as absent, which these required-field structs cannot express, so it
// reads them through its own optional-field input types.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementAction {
    pub from: String,
    pub quantity: String,
    pub memo: String,
    pub contract: String,
    /// The settlement's transaction type, `payment` under the XRPL profile
    /// (`xrpl_action_name`). Paying the MPT back to its own issuer destroys the
    /// amount, so the action names no `to` account.
    pub name: String,
    pub chain_id: String,
    pub trx_id: String,
    pub action_ordinal: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProof {
    pub block_num: String,
    pub block_id: String,
    pub last_irreversible_block_num: String,
    pub last_irreversible_block_id: String,
    /// Consensus time of the settlement block: the irreversible public-record
    /// timestamp of the CAPACITY consumption. RFC 3339 UTC, taken from the block
    /// that carries the settlement transaction. This is the substrate's "when", from
    /// which an issuer derives a "no-later-than" upper bound on the certificate's
    /// age — NOT a CERTCRYPT seal, NOT a document-existence notarization.
    pub block_timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchManifest {
    pub batch_id: String,
    pub window_id: String,
    pub leaf_count: String,
    pub total_quantity: String,
    pub settlement_root: String,
    pub system_id: String,
    pub rules_version: String,
    pub settlement_profile_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityConsumptionProof {
    pub total_quantity: String,
    /// The leaf's consumed quantity. The settlement-material contract field the
    /// verifier reads in CAPACITY_BINDING_VALID; the name must match across producer,
    /// verifier, fixtures, generator and spec.
    pub leaf_quantity: String,
    pub token_symbol: String,
    pub token_contract: String,
}

/// Field order matches the verifier's `canonicalJsonBytes([...])` for the leaf
/// preimage exactly (`settlement.binding/1` §6). Do not reorder — the leaf hash
/// depends on serialization order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafPreimage {
    pub v: String,
    pub system_id: String,
    pub rules_version: String,
    pub settlement_profile_id: String,
    pub batch_id: String,
    pub leaf_index: String,
    pub subtree_root: String,
    pub cost_commitment: String,
    pub consumed_quantity: String,
}

/// Version tag of the leaf preimage. It marks the preimage format, not a profile
/// version; there is no `/2`. Evolution before freeze follows `security-model/1`
/// evolution-and-freeze-policy.
pub const LEAF_VERSION: &str = "ccab1-leaf";

/// Field order matches the verifier's `canonicalJsonBytes([...])` for the batch
/// binding preimage exactly (`settlement.binding/1` §5). Do not reorder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchBindingPreimage {
    pub v: String,
    pub system_id: String,
    pub rules_version: String,
    pub settlement_profile_id: String,
    pub batch_id: String,
    pub window_id: String,
    pub leaf_count: String,
    pub total_quantity: String,
    pub settlement_root: String,
}

// ---------------------------------------------------------------------------
// Commitment sub-tree (leaf = sub-tree of accepted commitments).
//
// A settlement leaf is the Merkle root over the commitments accepted into that
// leaf (`subtree_root`). Each commitment carries its own inclusion path
// `commitment → subtree_root`, chained beneath the `leaf → settlement_root`
// path, so a single commitment's Proof of Independence verifies without the
// other commitments in the same leaf (`independence.proof/1 §7.10/§10.8`).
//
// This is a self-contained second Merkle level built on the *same* `merkle`
// primitives as the batch level — `compute_subtree_root` reuses
// `compute_leaf_hash`/`compute_merkle_root` and produces the `subtree_root`
// bound as the leaf's value.
// ---------------------------------------------------------------------------

/// Canonical preimage of one commitment node inside a leaf's sub-tree.
///
/// Insertion-ordered (NOT JCS), like [`LeafPreimage`]/[`BatchBindingPreimage`]:
/// the sub-tree leaf hash depends on field order, so it is fixed here and must
/// match the verifier's order in Step 2. The economic fields
/// (`consumed_quantity`/`cost_commitment`) stay per-leaf on the leaf preimage,
/// so a commitment node carries only its self-identifying id.
#[derive(Debug, Clone, Serialize)]
pub struct CommitmentLeafPreimage {
    pub v: String,
    pub commitment_id: String,
}

/// First level of the chained inclusion path: proves one commitment is a leaf
/// of the sub-tree whose root is `subtree_root`. The second level
/// (`subtree_root` as a leaf of the batch tree) is the [`SubmissionAssignmentProof`]
/// batch path.
///
/// This is **per-commitment** material: the producer derives one of these for
/// each accepted commitment when it composes that commitment's per-certificate
/// projection (`independence.proof/1 §7.10`). It is deliberately NOT
/// embedded in [`SubmissionAssignmentProof`] — a leaf's settlement-material
/// covers the leaf as a whole (one `subtree_root`), not any single commitment.
#[derive(Debug, Clone, Serialize)]
pub struct CommitmentInclusionProof {
    pub commitment_id: String,
    pub commitment_leaf_hash: String,
    pub commitment_index: String,
    pub commitment_siblings: Vec<String>,
    pub subtree_size: String,
}

/// Binds a leaf's `subtree_root` to its place in the batch tree
/// (`subtree_root → settlement_root`); `subtree_root` is the leaf's bound
/// value. The first inclusion level (`commitment → subtree_root`) is carried
/// per-commitment in [`CommitmentInclusionProof`], not here.
#[derive(Debug, Clone, Serialize)]
pub struct SubmissionAssignmentProof {
    pub subtree_root: String,
    pub leaf_index: String,
    pub leaf_preimage: LeafPreimage,
    pub leaf_hash: String,
    pub sibling_hashes: Vec<String>,
}

/// Version tag of the commitment sub-tree leaf preimage.
pub const COMMITMENT_LEAF_VERSION: &str = "ccab1-commit";

/// Build the commitment leaf hash for one `commitment_id` (the sub-tree leaf:
/// `SHA3-256(0x00 || ordered_json({v, commitment_id}))`).
pub(crate) fn commitment_leaf_hash(commitment_id: &str) -> Result<String, serde_json::Error> {
    let preimage = CommitmentLeafPreimage {
        v: COMMITMENT_LEAF_VERSION.to_string(),
        commitment_id: commitment_id.to_string(),
    };
    let bytes = ordered_json_bytes(&preimage)?;
    Ok(crate::merkle::compute_leaf_hash(&bytes))
}

/// Compute the `subtree_root` over the **accepted** commitments of one leaf,
/// returning the root and every commitment leaf hash in input order.
///
/// `commitment_ids` are the commitments that survived validation for this
/// leaf, in their canonical leaf order (the same order the inclusion proofs are
/// indexed against). Reuses the batch-level `merkle` primitives unchanged;
/// the two levels differ only in what they hash, not how.
///
/// **Invariant:** a leaf carries ≥1 accepted commitment. "0 accepted" is a
/// legitimate operational outcome of a submission-set (every commitment lost
/// the race and is rejected individually), but it is resolved *upstream*: the
/// issuance service forms no leaf and writes no settlement in that case, so this function
/// is never reached. Reaching it with an empty slice is therefore a caller
/// bug (a leaf formed that the model says must not exist), and it panics.
pub fn compute_subtree_root(
    commitment_ids: &[String],
) -> Result<(String, Vec<String>), serde_json::Error> {
    assert!(
        !commitment_ids.is_empty(),
        "a settlement leaf must carry at least one accepted commitment; \
         a submission-set with zero accepted commitments forms no leaf (resolved upstream)"
    );
    let leaf_hashes: Vec<String> = commitment_ids
        .iter()
        .map(|id| commitment_leaf_hash(id))
        .collect::<Result<_, _>>()?;
    let root = crate::merkle::compute_merkle_root(&leaf_hashes);
    Ok((root, leaf_hashes))
}

/// Build the `commitment → subtree_root` inclusion proof for the commitment at
/// `commitment_index` among `commitment_ids` (the accepted commitments of one
/// leaf). The returned proof self-verifies against the `subtree_root` from
/// [`compute_subtree_root`] over the same inputs.
pub fn build_commitment_inclusion_proof(
    commitment_ids: &[String],
    commitment_index: usize,
) -> Result<CommitmentInclusionProof, serde_json::Error> {
    let (_root, leaf_hashes) = compute_subtree_root(commitment_ids)?;
    let siblings = crate::merkle::generate_inclusion_proof(&leaf_hashes, commitment_index);
    Ok(CommitmentInclusionProof {
        commitment_id: commitment_ids[commitment_index].clone(),
        commitment_leaf_hash: leaf_hashes[commitment_index].clone(),
        commitment_index: commitment_index.to_string(),
        commitment_siblings: siblings,
        subtree_size: leaf_hashes.len().to_string(),
    })
}

/// Proves how the resolved capacity authorization became the consumed path of
/// this aggregated settlement (the aggregated settlement profile). Under the
/// zero-data profile the authorization is NOT named by a stable, correlating
/// `issuer_scope`/`capacity_authorization_ref`; it is identified by
/// `resolved_authorization_digest` = `SHA3-256(level1_binding.signing_bytes())`,
/// the digest of the system-domain Level-1 authorization the capacity evidence
/// carries and the verifier independently re-verifies. The verifier cross-checks
/// this digest against the evidence's `level1_binding`, so the bridge derives
/// from the resolved authorization artifact rather than restating a
/// cleartext scope.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationBridgeProof {
    pub resolved_authorization_digest: String,
    pub cost_commitment: String,
    pub consumed_quantity: String,
    pub batch_binding_preimage: BatchBindingPreimage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoherenceMaterial {
    pub system_id: String,
    pub rules_version: String,
    pub settlement_profile_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettlementMaterial {
    pub settlement_profile_id: String,
    pub settlement_action: SettlementAction,
    pub finality_proof: FinalityProof,
    pub batch_manifest: BatchManifest,
    pub capacity_consumption_proof: CapacityConsumptionProof,
    pub submission_assignment_proof: SubmissionAssignmentProof,
    /// One bridge per DISTINCT resolved authorization in the leaf.
    /// A leaf may group commitments under different Level-1 authorizations; the
    /// verifier selects the bridge matching the evidence it verifies. All entries
    /// share one `batch_binding_preimage` (the memo is batch-level).
    pub authorization_bridge_proofs: Vec<AuthorizationBridgeProof>,
    pub coherence_material: CoherenceMaterial,
}

/// The facts a settlement carries that originate on the chain: the fields of the
/// transaction that carried it. Everything the verifier checks structurally is
/// computed before the transaction is submitted, so the receipt only fills in
/// chain-identity fields.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SettlementReceipt {
    pub chain_id: String,
    pub trx_id: String,
    pub action_ordinal: String,
    pub block_num: u64,
    pub block_id: String,
    pub last_irreversible_block_num: u64,
    pub last_irreversible_block_id: String,
    /// Consensus time of the settlement block, RFC 3339 UTC, taken from the block
    /// that carries the settlement transaction.
    pub block_timestamp: String,
    /// What the settlement's `contract` field must name — on XRPL the MPT issuance
    /// id. It belongs to the deployment, not to the protocol, which is why it
    /// travels on the receipt instead of being compiled in.
    ///
    /// Empty when the producer resolves it from its own configuration instead. Whoever assembles the material must
    /// make sure ONE of the two paths supplies it: a signed
    /// `settlement_action.contract` that goes out empty is refused by a verifier
    /// on `CAPACITY_BINDING_VALID`, and a verifier that tolerates an empty
    /// EXPECTED value will not catch it on its own.
    pub action_contract: String,
    /// The account the settlement debited. Like `action_contract`, it belongs to
    /// the deployment. It becomes the signed `settlement_action.from`, which a
    /// verifier requires to equal the rules domain's `xrpl_settlement_account`.
    ///
    /// Empty when the producer resolves it from its own configuration instead;
    /// anchoring material is never assembled with neither.
    pub settlement_account: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SettlementAssemblyError {
    #[error("settlement submitter failed: {0}")]
    Submitter(String),
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Compute one settlement-leaf hash from its bound fields — the same
/// [`LeafPreimage`] + `compute_leaf_hash` the assembler uses for the target leaf.
/// The producer calls this for EVERY leaf of a closing batch to build the
/// `batch_leaf_hashes` it then feeds back as the assembler's `batch_leaf_hashes`,
/// so the assembler's target-leaf hash is guaranteed to match its slot in the
/// batch tree. Field order is load-bearing (insertion-ordered preimage).
///
/// `rules_version` is supplied by the caller: a producer passes the domain its
/// deployment settles under, while the conformance generator and the parity
/// vectors pass `rules/conformance` so the contract material is
/// environment-agnostic. It MUST match the `rules_version` later fed to
/// the assembler for the same batch, or the recomputed leaf will not match its
/// slot.
pub fn leaf_hash_for(
    rules_version: &str,
    batch_id: &str,
    leaf_index: usize,
    subtree_root: &str,
    cost_commitment: &str,
    consumed_quantity: &str,
) -> Result<String, serde_json::Error> {
    // The profile is resolved FROM the rules version, not taken from a constant:
    // the rules domain selects the profile, and this preimage is hashed
    // into the batch tree, so a mismatched profile silently produces a leaf that
    // will not match its slot. An unknown rules domain falls back to the default
    // profile, for callers that pass an ad-hoc domain; every domain in the tree
    // resolves, and a test pins that.
    let profile =
        settlement_profile_for_rules(rules_version).unwrap_or(SETTLEMENT_PROFILE_AGGREGATED_XRPL);
    let leaf_preimage = LeafPreimage {
        v: LEAF_VERSION.to_string(),
        system_id: SYSTEM_ID.to_string(),
        rules_version: rules_version.to_string(),
        settlement_profile_id: profile.to_string(),
        batch_id: batch_id.to_string(),
        leaf_index: leaf_index.to_string(),
        subtree_root: subtree_root.to_string(),
        cost_commitment: cost_commitment.to_string(),
        consumed_quantity: consumed_quantity.to_string(),
    };
    let bytes = ordered_json_bytes(&leaf_preimage)?;
    Ok(crate::merkle::compute_leaf_hash(&bytes))
}

/// SHA3-256 of `bytes` as lowercase hex.
pub fn sha3_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

/// Serialize a value with insertion-ordered `serde_json` (NOT JCS). Used for
/// the two preimages whose hashing the verifier defines over insertion order.
pub fn ordered_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- commitment sub-tree (Step 1) ---

    fn commitment_ids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("commit:{i:064x}")).collect()
    }

    #[test]
    fn single_commitment_subtree_root_is_its_leaf_hash() {
        let ids = commitment_ids(1);
        let (root, leaves) = compute_subtree_root(&ids).unwrap();
        assert_eq!(leaves.len(), 1);
        // A one-leaf Merkle tree's root is the leaf itself (merkle.rs rule).
        assert_eq!(root, leaves[0]);
    }

    #[test]
    fn commitment_inclusion_self_verifies_for_every_commitment() {
        // Odd cardinality (5) exercises the sub-tree's odd-promotion path.
        let ids = commitment_ids(5);
        let (root, _) = compute_subtree_root(&ids).unwrap();
        for index in 0..ids.len() {
            let proof = build_commitment_inclusion_proof(&ids, index).unwrap();
            assert_eq!(proof.subtree_size, "5");
            assert_eq!(proof.commitment_id, ids[index]);
            assert!(
                crate::merkle::verify_inclusion_proof(
                    &proof.commitment_leaf_hash,
                    index,
                    &proof.commitment_siblings,
                    &root,
                    ids.len(),
                ),
                "commitment {index} must include against subtree_root"
            );
        }
    }

    #[test]
    #[should_panic(expected = "at least one accepted commitment")]
    fn empty_subtree_is_a_caller_bug_not_a_value() {
        // "0 accepted" is resolved upstream (no leaf is formed); reaching the
        // sub-tree layer with an empty set violates the leaf invariant.
        let _ = compute_subtree_root(&[]);
    }

    #[test]
    fn subtree_root_changes_with_commitment_set() {
        // Distinct accepted sets must yield distinct roots (no collision across
        // leaves): the root binds exactly the commitments it covers.
        let (a, _) = compute_subtree_root(&commitment_ids(3)).unwrap();
        let (b, _) = compute_subtree_root(&commitment_ids(4)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn leaf_hash_for_is_deterministic_and_order_sensitive() {
        // The leaf hash is a pure function of its bound fields; same inputs →
        // same hash, and a changed bound field → a different hash.
        let h1 = leaf_hash_for(
            "rules/conformance",
            "batch-test",
            0,
            &"aa".repeat(32),
            &"44".repeat(32),
            "1.00",
        )
        .unwrap();
        let h2 = leaf_hash_for(
            "rules/conformance",
            "batch-test",
            0,
            &"aa".repeat(32),
            &"44".repeat(32),
            "1.00",
        )
        .unwrap();
        assert_eq!(h1, h2);
        let h3 = leaf_hash_for(
            "rules/conformance",
            "batch-test",
            1, // different leaf_index
            &"aa".repeat(32),
            &"44".repeat(32),
            "1.00",
        )
        .unwrap();
        assert_ne!(h1, h3);
    }
}
