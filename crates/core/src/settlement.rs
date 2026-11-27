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

//! Settlement cable TYPES + deterministic Merkle/hash primitives (node side).
//!
//! Producing the settlement belongs to the issuance service. The node
//! PROPOSES and PACKAGES; the service EXECUTES and PRODUCES the
//! settlement.
//!
//! What the node legitimately needs is the cable TYPES (so `verification_package`
//! can carry the `SettlementMaterial` the issuance service produces and the
//! `CommitmentInclusionProof` it builds) and the deterministic Merkle/hash
//! primitives (anti-drift: one impl in Rust). Both live in
//! `capacity_artifacts::settlement` and are re-exported here, under
//! `certcrypt_node_core::settlement::{...}`.

// Cable types + deterministic primitives live in `capacity-artifacts`, in the
// protocol core: one implementation, so a digest cannot drift between the party
// that produces it and the party that checks it. Re-exported here for
// `certcrypt_node_core::settlement::{...}` consumers.
pub use capacity_artifacts::settlement::{
    build_commitment_inclusion_proof, compute_subtree_root, leaf_hash_for,
    settlement_profile_for_rules, AuthorizationBridgeProof, BatchBindingPreimage, BatchManifest,
    CapacityConsumptionProof, CoherenceMaterial, CommitmentInclusionProof, CommitmentLeafPreimage,
    FinalityProof, LeafPreimage, SettlementAction, SettlementAssemblyError, SettlementMaterial,
    SettlementReceipt, SubmissionAssignmentProof, COMMITMENT_LEAF_VERSION, LEAF_VERSION,
    SETTLEMENT_MEMO_PREFIX, SETTLEMENT_PROFILE_AGGREGATED_XRPL, SETTLEMENT_TOKEN_SYMBOL, SYSTEM_ID,
};
