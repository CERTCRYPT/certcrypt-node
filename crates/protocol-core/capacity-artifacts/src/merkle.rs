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

//! Aggregated-settlement Merkle tree.
//!
//! Byte-exact port of the reference verifier's `settlement.binding/1` §6
//! construction (`certcrypt-verifier-toolkit-js/core/crypto/merkle.ts`).
//! Any divergence here silently produces a `settlement_root` the verifier
//! rejects, so the rules are kept identical:
//!
//! - leaf hash:  `SHA3-256(0x00 || canonical_leaf_preimage_bytes)`
//! - node hash:  `SHA3-256(0x01 || left || right)`
//! - odd cardinality: the final child is promoted unchanged when it has no
//!   sibling at a level.
//!
//! Hashes are carried as 64-char lowercase hex strings, matching the wire form
//! the verifier compares against.

use crate::canonical::is_lower_hex_64;
use sha3::{Digest, Sha3_256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// `SHA3-256(0x00 || canonical_bytes)` as lowercase hex.
pub fn compute_leaf_hash(canonical_bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(canonical_bytes);
    hex::encode(hasher.finalize())
}

/// `SHA3-256(0x01 || left || right)` as lowercase hex. `left`/`right` are
/// 64-char lowercase hex node hashes: every caller passes hashes this module
/// computed, or siblings [`verify_inclusion_proof`] has already checked are
/// canonical, so the decode cannot fail on adversary-supplied input.
fn compute_node_hash(left_hex: &str, right_hex: &str) -> String {
    let left = hex::decode(left_hex).unwrap_or_default();
    let right = hex::decode(right_hex).unwrap_or_default();
    let mut hasher = Sha3_256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(&left);
    hasher.update(&right);
    hex::encode(hasher.finalize())
}

/// Compute the Merkle root from leaf hashes (odd child promoted unchanged).
///
/// Mirrors `computeMerkleRoot` in the verifier. Panics on an empty leaf set —
/// a settlement window always carries at least one submission set.
pub fn compute_merkle_root(leaf_hashes: &[String]) -> String {
    assert!(
        !leaf_hashes.is_empty(),
        "cannot compute Merkle root of empty leaf set"
    );
    if leaf_hashes.len() == 1 {
        return leaf_hashes[0].clone();
    }

    let mut level: Vec<String> = leaf_hashes.to_vec();
    while level.len() > 1 {
        let mut next: Vec<String> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(compute_node_hash(&level[i], &level[i + 1]));
            } else {
                next.push(level[i].clone());
            }
            i += 2;
        }
        level = next;
    }
    level.into_iter().next().unwrap()
}

/// Generate the bottom-up sibling hashes (inclusion proof) for a leaf.
///
/// Mirrors `generateInclusionProof` in the verifier.
pub fn generate_inclusion_proof(leaf_hashes: &[String], leaf_index: usize) -> Vec<String> {
    if leaf_hashes.len() <= 1 {
        return Vec::new();
    }

    let mut siblings: Vec<String> = Vec::new();
    let mut level: Vec<String> = leaf_hashes.to_vec();
    let mut idx = leaf_index;

    while level.len() > 1 {
        let has_sibling = idx % 2 == 1 || idx + 1 < level.len();
        if has_sibling {
            // `idx % 2` kept verbatim (not `is_multiple_of`) to stay a
            // line-for-line port of the verifier's merkle.ts for review parity.
            #[allow(clippy::manual_is_multiple_of)]
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            siblings.push(level[sibling_idx].clone());
        }
        let mut next: Vec<String> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(compute_node_hash(&level[i], &level[i + 1]));
            } else {
                next.push(level[i].clone());
            }
            i += 2;
        }
        level = next;
        idx /= 2;
    }

    siblings
}

/// Verify an inclusion proof against an expected root.
///
/// Mirrors `verifyInclusionProof` in the verifier exactly, including the
/// orientation and odd-promotion rules. Provided so node can self-check the
/// proofs it emits before handing them to the verifier.
pub fn verify_inclusion_proof(
    leaf_hash: &str,
    leaf_index: usize,
    sibling_hashes: &[String],
    expected_root: &str,
    tree_size: usize,
) -> bool {
    // Bounds: an empty tree has no leaves to prove, and a leaf_index at or past
    // the tree size names a leaf that does not exist. Without this guard a
    // single-leaf tree (`tree_size == 1`) skips the `while` entirely and would
    // accept ANY `leaf_index` against the root — a forged inclusion. Reject up
    // front so both callers (node self-check + settlement verification) are
    // protected by the one shared implementation.
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }
    // Every hash this fold consumes or compares is a 64-char LOWERCASE hex
    // string, and anything else fails here, before the fold: an uppercase or
    // non-hex sibling is not another spelling of a valid proof, and it must
    // never reach a decode as a panic (a whole request turned into a server
    // error by one malformed entry).
    if !is_lower_hex_64(leaf_hash)
        || !is_lower_hex_64(expected_root)
        || !sibling_hashes.iter().all(|s| is_lower_hex_64(s))
    {
        return false;
    }

    let mut current_hash = leaf_hash.to_string();
    let mut sibling_index = 0usize;
    let mut level_width = tree_size;
    let mut level = 0u32;

    while level_width > 1 {
        let is_right = ((leaf_index >> level) & 1) == 1;
        let has_sibling = is_right || (leaf_index >> level) + 1 < level_width;

        if !has_sibling {
            level_width = level_width.div_ceil(2);
            level += 1;
            continue;
        }

        let sibling = match sibling_hashes.get(sibling_index) {
            Some(s) => s,
            None => return false,
        };
        sibling_index += 1;

        current_hash = if is_right {
            compute_node_hash(sibling, &current_hash)
        } else {
            compute_node_hash(&current_hash, sibling)
        };

        level_width = level_width.div_ceil(2);
        level += 1;
    }

    sibling_index == sibling_hashes.len() && current_hash == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let leaf = compute_leaf_hash(b"only");
        assert_eq!(compute_merkle_root(std::slice::from_ref(&leaf)), leaf);
    }

    #[test]
    fn proof_round_trips_for_each_leaf_in_a_two_leaf_tree() {
        let leaves: Vec<String> = (0..2).map(|i| compute_leaf_hash(&[i as u8])).collect();
        let root = compute_merkle_root(&leaves);
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = generate_inclusion_proof(&leaves, idx);
            assert!(verify_inclusion_proof(
                leaf,
                idx,
                &proof,
                &root,
                leaves.len()
            ));
        }
    }

    #[test]
    fn proof_round_trips_for_odd_cardinality_tree() {
        // 5 leaves exercises the odd-promotion path at two levels.
        let leaves: Vec<String> = (0..5).map(|i| compute_leaf_hash(&[i as u8])).collect();
        let root = compute_merkle_root(&leaves);
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = generate_inclusion_proof(&leaves, idx);
            assert!(
                verify_inclusion_proof(leaf, idx, &proof, &root, leaves.len()),
                "leaf {idx} failed inclusion"
            );
        }
    }

    #[test]
    fn single_leaf_tree_rejects_any_nonzero_or_oob_index() {
        // Regression: a one-leaf tree skips the `while` entirely. Without the
        // bounds guard ANY leaf_index verified true against the root (the root IS
        // the leaf). Index 0 with an empty proof is the only valid claim.
        let leaf = compute_leaf_hash(b"only");
        assert!(
            verify_inclusion_proof(&leaf, 0, &[], &leaf, 1),
            "index 0 of a 1-leaf tree is the leaf itself"
        );
        // A forged index past the tree must be rejected, not silently accepted.
        assert!(!verify_inclusion_proof(&leaf, 1, &[], &leaf, 1));
        assert!(!verify_inclusion_proof(&leaf, 7, &[], &leaf, 1));
    }

    #[test]
    fn empty_tree_and_oob_index_are_rejected() {
        let leaf = compute_leaf_hash(b"x");
        assert!(
            !verify_inclusion_proof(&leaf, 0, &[], &leaf, 0),
            "tree_size 0"
        );
        // leaf_index == tree_size is out of range (indices are 0..tree_size).
        let leaves: Vec<String> = (0..4).map(|i| compute_leaf_hash(&[i as u8])).collect();
        let root = compute_merkle_root(&leaves);
        let proof = generate_inclusion_proof(&leaves, 0);
        assert!(!verify_inclusion_proof(&leaves[0], 4, &proof, &root, 4));
    }

    #[test]
    fn non_canonical_sibling_hex_fails_without_panicking() {
        let leaves: Vec<String> = (0..4).map(|i| compute_leaf_hash(&[i as u8])).collect();
        let root = compute_merkle_root(&leaves);
        let proof = generate_inclusion_proof(&leaves, 0);
        assert!(verify_inclusion_proof(&leaves[0], 0, &proof, &root, 4));

        let mut upper = proof.clone();
        upper[0] = upper[0].to_uppercase();
        assert!(!verify_inclusion_proof(&leaves[0], 0, &upper, &root, 4));

        let mut not_hex = proof.clone();
        not_hex[1] = "zz".repeat(32);
        assert!(!verify_inclusion_proof(&leaves[0], 0, &not_hex, &root, 4));

        let mut short = proof.clone();
        short[0].pop();
        assert!(!verify_inclusion_proof(&leaves[0], 0, &short, &root, 4));

        assert!(!verify_inclusion_proof(
            &leaves[0],
            0,
            &proof,
            &root.to_uppercase(),
            4
        ));
    }

    #[test]
    fn wrong_root_fails_verification() {
        let leaves: Vec<String> = (0..3).map(|i| compute_leaf_hash(&[i as u8])).collect();
        let proof = generate_inclusion_proof(&leaves, 1);
        assert!(!verify_inclusion_proof(
            &leaves[1],
            1,
            &proof,
            "00".repeat(32).as_str(),
            leaves.len()
        ));
    }
}
