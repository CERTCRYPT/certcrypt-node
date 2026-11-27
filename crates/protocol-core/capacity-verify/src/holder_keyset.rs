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

//! Holder operation-key tree (Merkle of operation keys) — the secret-bearing
//! PRODUCER.
//!
//! Implements the offline capacity-evidence projection mechanism:
//! instead of authorizing one stable `holder_public_key`, the Level-2
//! authorization commits to a Merkle root over a SET of per-operation holder
//! keys (`holder_key_set_root`). Each `capacity.commitment/1` is signed by a
//! DISTINCT leaf key (never reused), and the offline verifier checks both the
//! ML-DSA signature against that leaf and the leaf's Merkle inclusion in the
//! authorized root.
//!
//! This lets the offline verifier re-verify the holder signature for real (not an
//! opaque commitment): two commitments use different, non-reused leaf keys and
//! the per-operation pseudonyms (`holder`/`pool`/`authorization`) rotate under a
//! fresh `operation_salt` (see [`capacity_artifacts::pseudonym`]).
//!
//! Linkability boundary (NOT a leak — by design; see public docs
//! `design-principles/unlinkability.md` §"Protocol surface vs artifact surface").
//! The `holder_key_set_root` is STABLE per authorized key-set and DOES travel in
//! clear — but only on the ARTIFACT SURFACE: it rides the capacity-evidence inside
//! the verification-package (holder → verifier, a private/local channel) and the
//! Level-1 binding signs it. It does NOT reach the PROTOCOL SURFACE: nothing the
//! protocol emits on-chain carries it (the settlement memo binds only the
//! aggregated `settlement_root` + batch fields, not the holder root), and CERTCRYPT
//! runs no per-issuer feed/log/aggregator over it. So CERTCRYPT's structural
//! unlinkability (a property of the protocol surface) holds; correlation an
//! observer performs over artifacts circulating off that surface is exactly what
//! the docs permit. Guarantee: zero-PII + protocol-surface unlinkability;
//! NOT artifact-surface unobservability once the package leaves the verifier.
//!
//! No new cryptography: the leaf/node hashing reuses the exact Merkle rules of
//! [`crate::merkle`], and the keys are standard ML-DSA-65 from
//! [`crate::mldsa`]. The only design choice is a parameter — the tree size —
//! which bounds how many per-operation leaf keys one authorization covers before
//! re-issuance (offline, in window). Operations under one key-set share its root
//! (see linkability boundary above), so the tree size bounds operations-per-root,
//! not an unlinkability budget.
//!
//! The verification-side types ([`OperationKeyDisclosure`] and
//! [`operation_key_leaf_hash`]) are the closed-schema artifacts in
//! `capacity-artifacts`; this module owns the secret-bearing producer
//! ([`HolderKeySet`]). Both producer and verifier ([`crate::capacity_evidence`])
//! live in this shared crate so the online submit path and the offline node run
//! the SAME code — no producer/verifier drift across the issuance service and the node.

use crate::capacity_evidence::{operation_key_leaf_hash, OperationKeyDisclosure};
use crate::mldsa;

/// One operation key: an ML-DSA-65 keypair that signs at most ONE commitment.
#[derive(Clone)]
pub struct OperationKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl std::fmt::Debug for OperationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret key material.
        f.debug_struct("OperationKey")
            .field("public_key_len", &self.public_key.len())
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

/// A holder's authorized operation-key tree. The Level-2 authorization commits
/// to [`Self::root`]; each commitment reveals one leaf + its inclusion proof.
#[derive(Debug, Clone)]
pub struct HolderKeySet {
    keys: Vec<OperationKey>,
    leaf_hashes: Vec<String>,
    root: String,
}

impl HolderKeySet {
    /// Generate a key set of `size` operation keys. `size` bounds the number of
    /// operations (one leaf each) this authorization covers. The
    /// caller (holder setup, offline, once per authorization) custodies the
    /// secret keys locally.
    pub fn generate(size: usize) -> Self {
        assert!(
            size > 0,
            "holder key set must have at least one operation key"
        );
        let keys: Vec<OperationKey> = (0..size)
            .map(|_| {
                let (public_key, secret_key) = mldsa::keypair();
                OperationKey {
                    public_key,
                    secret_key,
                }
            })
            .collect();
        let leaf_hashes: Vec<String> = keys
            .iter()
            .map(|k| operation_key_leaf_hash(&k.public_key))
            .collect();
        let root = crate::merkle::compute_merkle_root(&leaf_hashes);
        Self {
            keys,
            leaf_hashes,
            root,
        }
    }

    /// Build a key set from already-generated keys (e.g. restored from holder
    /// custody). Recomputes leaves and root deterministically.
    pub fn from_keys(keys: Vec<OperationKey>) -> Self {
        assert!(!keys.is_empty(), "holder key set must not be empty");
        let leaf_hashes: Vec<String> = keys
            .iter()
            .map(|k| operation_key_leaf_hash(&k.public_key))
            .collect();
        let root = crate::merkle::compute_merkle_root(&leaf_hashes);
        Self {
            keys,
            leaf_hashes,
            root,
        }
    }

    /// The `holder_key_set_root` the Level-2 authorization commits to.
    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The operation key at `leaf_index` (for signing one commitment).
    ///
    /// MUST: each leaf signs at most ONE commitment.
    /// Reusing a leaf reintroduces correlation between the two commitments that
    /// share it. This is an emission invariant of the holder; the offline
    /// verifier cannot detect reuse (it has no global state), so the holder is
    /// responsible for never handing the same `leaf_index` to two commitments.
    /// Single-consumption of the commitment at settlement partially backstops
    /// it.
    pub fn key(&self, leaf_index: usize) -> Option<&OperationKey> {
        self.keys.get(leaf_index)
    }

    /// The inclusion proof binding leaf `leaf_index` to [`Self::root`].
    pub fn inclusion_proof(&self, leaf_index: usize) -> Vec<String> {
        crate::merkle::generate_inclusion_proof(&self.leaf_hashes, leaf_index)
    }

    /// The full per-operation disclosure for a commitment signed by
    /// `leaf_index`: the leaf public key, its index, and its inclusion proof.
    /// This is what travels in the capacity evidence (the secret key never
    /// leaves the holder).
    ///
    /// MUST: see [`Self::key`] — `leaf_index` must not be reused across
    /// commitments.
    pub fn disclosure(&self, leaf_index: usize) -> Option<OperationKeyDisclosure> {
        let key = self.keys.get(leaf_index)?;
        Some(OperationKeyDisclosure {
            leaf_index,
            public_key_b64: base64_encode(&key.public_key),
            inclusion_proof: self.inclusion_proof(leaf_index),
            tree_size: self.keys.len(),
        })
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_leaves_share_only_the_root() {
        let ks = HolderKeySet::generate(4);
        let d0 = ks.disclosure(0).unwrap();
        let d1 = ks.disclosure(1).unwrap();
        // Two operations expose different leaf keys (not linkable by key)...
        assert_ne!(d0.public_key_b64, d1.public_key_b64);
        // ...but both bind to the same authorized root.
        assert!(d0.verify_membership(ks.root()));
        assert!(d1.verify_membership(ks.root()));
    }

    #[test]
    fn membership_fails_against_wrong_root() {
        let ks = HolderKeySet::generate(3);
        let d = ks.disclosure(1).unwrap();
        assert!(d.verify_membership(ks.root()));
        assert!(!d.verify_membership(&"00".repeat(32)));
    }

    #[test]
    fn tampered_leaf_key_fails_membership() {
        let ks = HolderKeySet::generate(4);
        let mut d = ks.disclosure(2).unwrap();
        // Swap in a foreign key not in the tree.
        let (foreign_pk, _) = mldsa::keypair();
        d.public_key_b64 = base64_encode(&foreign_pk);
        assert!(!d.verify_membership(ks.root()));
    }

    #[test]
    fn disclosure_exposes_only_position_not_identity() {
        // (tree_size, leaf_index) is acceptable public metadata; the disclosure
        // must NOT carry any stable identity (only a per-operation leaf key,
        // its index, the tree size, and the inclusion proof).
        let ks = HolderKeySet::generate(4);
        let d = ks.disclosure(2).unwrap();
        assert_eq!(d.leaf_index, 2);
        assert_eq!(d.tree_size, 4);
        // Serialized disclosure has exactly the position + key + proof fields.
        let json = serde_json::to_value(&d).unwrap();
        let obj = json.as_object().unwrap();
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "inclusion_proof",
                "leaf_index",
                "public_key_b64",
                "tree_size"
            ]
        );
    }

    #[test]
    fn signature_verifies_against_disclosed_leaf() {
        let ks = HolderKeySet::generate(2);
        let key = ks.key(0).unwrap();
        let msg = b"capacity.commitment signing bytes";
        let sig = mldsa::sign_detached(&key.secret_key, msg).unwrap();
        let d = ks.disclosure(0).unwrap();
        let pk = d.public_key().unwrap();
        assert!(mldsa::verify_detached(&pk, &sig, msg).is_ok());
        assert!(d.verify_membership(ks.root()));
    }
}
