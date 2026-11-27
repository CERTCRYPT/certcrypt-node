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

//! Zero-data capacity evidence — wire types.
//!
//! `capacity.evidence/1` is the projected, unlinkable view of a
//! `capacity.commitment/1` (and the authorization that authorizes it): stable
//! identifiers become operation-scoped pseudonyms and the stable holder key
//! becomes a non-reused per-operation leaf key proven to belong to a
//! system-domain-authorized key-set root. It is what lets the OFFLINE verifier
//! re-run the capacity proof WITHOUT receiving the correlators.
//!
//! These are CLOSED-SCHEMA wire types — they live here in `capacity-artifacts`,
//! alongside the other artifact types (`CapacityCommitmentV1`,
//! `CapacityHolderAuthorizationV1`), because lower layers (e.g.
//! `submission-set/1`) embed them. The OFFLINE VERIFIER
//! (`verify_capacity_evidence`) lives in `capacity-verify` (it needs ML-DSA and
//! manifest resolution); the PRODUCER (`assemble_evidence`, with the secrets)
//! lives alongside it. Both consume these types.

use crate::capacity_holder_authorization::Level1AuthorizationBinding;
use crate::merkle;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const ZERO_DATA_PROFILE: &str = "zero-data.unlinkable";

/// Domain-separation prefix for an operation-key leaf: `SHA3-256(0x00 || pk)`.
/// Mirrors the leaf rule of [`merkle::compute_leaf_hash`] applied to the raw
/// public key bytes.
const KEY_LEAF_PREFIX: u8 = 0x00;

/// The leaf hash of an operation public key: `SHA3-256(0x00 || public_key)`.
pub fn operation_key_leaf_hash(public_key: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update([KEY_LEAF_PREFIX]);
    hasher.update(public_key);
    hex::encode(hasher.finalize())
}

/// What the holder publishes per commitment so the verifier can bind the
/// signing key to the authorized root without seeing the other leaves or a
/// stable key.
///
/// `(tree_size, leaf_index)` is **public metadata, acceptable by design**:
/// it does not correlate certificates. The reason is that index
/// assignment does not follow an observable temporal order — the holder may
/// assign leaves in any order and from a sparse tree, so `leaf_index` carries
/// no timing or sequence signal an observer could use to link operations. What
/// would identify (the stable key, the holder id, the authorization id) is
/// never exposed: the leaf key is per-operation and the ids are projected to
/// pseudonyms. The key-set root does travel in clear, so artifacts of one key
/// set are recognizable as such by whoever holds them; the leaf position adds
/// nothing to that.
///
/// No signature covers this object, and `tree_size` is not committed to by the
/// root, so two disclosures with different bytes can prove the same membership.
/// It is therefore never an identity: exclusivity is keyed on the signed
/// commitment ([`ProjectedCommitment::signed_digest_hex`]). Closed schema: an
/// additional member is a parse error, not a field to ignore.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationKeyDisclosure {
    pub leaf_index: usize,
    pub public_key_b64: String,
    pub inclusion_proof: Vec<String>,
    pub tree_size: usize,
}

impl OperationKeyDisclosure {
    /// Verify that this disclosed leaf key belongs to `authorized_root`.
    /// Returns false if the inclusion proof does not bind the
    /// leaf to the root.
    pub fn verify_membership(&self, authorized_root: &str) -> bool {
        let pk = match base64_decode(&self.public_key_b64) {
            Some(b) => b,
            None => return false,
        };
        let leaf_hash = operation_key_leaf_hash(&pk);
        merkle::verify_inclusion_proof(
            &leaf_hash,
            self.leaf_index,
            &self.inclusion_proof,
            authorized_root,
            self.tree_size,
        )
    }

    /// The raw leaf public key bytes, for ML-DSA signature verification.
    pub fn public_key(&self) -> Option<Vec<u8>> {
        base64_decode(&self.public_key_b64)
    }
}

/// The projected, unlinkable view of a `capacity.commitment/1` that the holder
/// signs with a per-operation leaf key. Identifying fields are pseudonyms;
/// publishable fields are carried in clear. Field order is the
/// canonical signing order — do not reorder (the leaf signature depends on it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectedCommitment {
    /// Publishable in clear.
    pub commitment_version: String,
    pub system_id: String,
    pub system_root_fingerprint: String,
    pub rules_version: String,
    /// Projected: pseudonym(authorization) — binds to the authorization without
    /// revealing `authorization_id`.
    pub authorization_pseudonym: String,
    /// Projected: pseudonym(holder).
    pub holder_pseudonym: String,
    /// Projected: pseudonym(pool).
    pub pool_pseudonym: String,
    /// Publishable in clear: the certificate content digest.
    pub certificate_commitment_digest: String,
    /// Publishable: capacity units carried as the consumed quantity string.
    pub consumed_quantity: String,
    /// Publishable: the issuer-declared effective units for this commitment's
    /// subject, the per-subject economic quantity bound by the `cost_commitment`
    /// preimage (`submission-set/1 §13.2`): a non-collection subject declares
    /// `"1"`, a collection subject declares its `declared_cardinality`. Distinct
    /// from `consumed_quantity` (the burned capacity). A canonical decimal /
    /// unsigned-integer string, never a number. An issuer declaration carried in
    /// the signed artifact path — not a separately supplied API parameter
    /// (`submission-set/1 §13.1`).
    pub declared_effective_units: String,
    /// Publishable with reduced precision: RFC3339 truncated to
    /// second. Carried so the verifier can run the temporal conditions.
    pub issued_at: String,
    pub expires_at: String,
}

impl ProjectedCommitment {
    /// Canonical bytes the per-operation leaf key signs. Insertion-ordered
    /// `serde_json` (NOT JCS): the struct field order IS the canonical order.
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("ProjectedCommitment serializes")
    }

    /// `SHA3-256(signing_bytes())` as lowercase hex: the identity of the
    /// commitment the holder signed, and so the key on which replay and
    /// exclusivity are enforced (`capacity.evidence/1` §7.2,
    /// `submission-set/1` §9.1). Unlike the evidence digest it does not move
    /// when the unsigned operation-key disclosure is re-encoded, and it does not
    /// depend on the hedged signature value.
    pub fn signed_digest_hex(&self) -> String {
        hex::encode(Sha3_256::digest(self.signing_bytes()))
    }
}

/// The publishable projection of the Level-2 authorization. The
/// stable `holder_public_key` is replaced by `holder_key_set_root` (the Merkle
/// commitment to the operation-key tree). Identifying ids are projected.
///
/// The `holder_key_set_root` is NOT a trusted input: it is bound by the
/// system-domain Level-1 signature (`level1_binding` + `level1_signature_b64`),
/// which the verifier checks first. Without that check, an attacker could
/// fabricate a root; with it, the root is anchored to a key the attacker does
/// not control.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectedAuthorization {
    pub system_id: String,
    pub rules_version: String,
    pub system_root_fingerprint: String,
    pub authorized_role: String,
    /// Level-1 system-domain kid — public by design (it is the manifest key,
    /// it does not correlate holders).
    pub authorization_issuer_kid: String,
    pub valid_from: String,
    pub valid_until: String,
    /// Replaces the stable holder public key: the Merkle root of the
    /// authorized operation-key set. Anchored by `level1_signature_b64`.
    pub holder_key_set_root: String,
    /// The exact binding the system-domain signed. The verifier
    /// recomputes this from the fields above and checks it equals what the
    /// signature covers.
    pub level1_binding: Level1AuthorizationBinding,
    /// System-domain Level-1 COMPOSITE signature (`composite-signature/1`) over
    /// `M' = composite_m_prime(profile_alg, SHA3-256(level1_binding.signing_bytes()))`.
    /// AND over all components. This is the trust anchor: it proves the
    /// `holder_key_set_root` was authorized by the system-domain (PQ + classical
    /// floor), not fabricated by the holder. Wire: `alg`/`mode`/`signatures[]`.
    pub level1_signature: crate::composite_sig::CompositeSignatureWire,
    /// Projected: pseudonym(authorization) — must match the commitment's.
    pub authorization_pseudonym: String,
    /// Projected: pseudonym(holder) — must match the commitment's.
    pub holder_pseudonym: String,
}

/// The complete zero-data capacity evidence carried under
/// `supporting_material.capacity_evidence`. Its canonical digest is bound into
/// the `IndependenceProofV1` — that is the anti-splicing anchor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapacityEvidence {
    /// Profile marker: the unlinkable zero-data profile.
    pub profile: String,
    /// Public per-operation salt: the verifier recomputes pseudonyms
    /// with this; a fresh salt per operation is what makes operations
    /// unlinkable.
    pub operation_salt_hex: String,
    pub projected_authorization: ProjectedAuthorization,
    pub projected_commitment: ProjectedCommitment,
    /// The per-operation leaf key + its Merkle inclusion proof to the
    /// authorized `holder_key_set_root`.
    pub operation_key: OperationKeyDisclosure,
    /// Holder's ML-DSA-65 signature over `projected_commitment.signing_bytes()`,
    /// made with the disclosed leaf key. Base64.
    pub commitment_signature_b64: String,
}

impl CapacityEvidence {
    /// Canonical digest bound into the `IndependenceProofV1`.
    ///
    /// Uses RFC 8785 JCS (sorted keys) — NOT insertion order. Rationale: unlike
    /// the projected-commitment signing bytes (which a signature covers and so
    /// must be byte-stable in declaration order), this digest only needs to be
    /// deterministic and identical across languages. The whole `CapacityEvidence`
    /// is deeply nested; depending on struct field order would make Rust
    /// `serde_json::to_vec` and TS `JSON.stringify` diverge. JCS sorts
    /// keys canonically on both sides, so the digest matches regardless of
    /// declaration order.
    pub fn evidence_digest_hex(&self) -> String {
        let bytes = serde_jcs::to_vec(self).expect("CapacityEvidence canonicalizes");
        hex::encode(Sha3_256::digest(&bytes))
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .ok()
}
