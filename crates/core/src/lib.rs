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

//! `certcrypt-node-core` — reusable issuer-node primitives.
//!
//! This crate owns the local complexity on the path from issuer-side activity
//! to an offline-verifiable `Independent` result:
//!
//! - [`merkle`] — the aggregated-settlement Merkle tree (a byte-exact port of
//!   the reference verifier's aggregated settlement construction).
//! - [`settlement`] — the settlement cable TYPES + deterministic Merkle/hash
//!   primitives (re-exported from `capacity-artifacts`) the node needs to carry
//!   and package the `settlement-material` the issuance service produces.
//!   Producing the settlement belongs to the issuance service — the node
//!   PROPOSES and PACKAGES; the service EXECUTES and PRODUCES the settlement.
//!
//! Canonicalization, digests, and artifact types come verbatim from
//! `capacity-artifacts` / `capacity-verify` in `crates/protocol-core/`, so there
//! is exactly one JCS/digest implementation across this surface.
//! Node never re-implements them: a divergent byte would silently break the
//! verifier.

pub mod operator_receipt;
pub mod settlement;
pub mod submission_set_builder;

// The Merkle tree, the zero-data evidence wire types, the offline verifier, AND
// the producer (`assemble_evidence` + `HolderKeySet` + `pseudonym`) live in the
// protocol core, so every party runs ONE producer and ONE verifier — no drift.
// Re-exported here so node consumers reach them through
// `certcrypt_node_core::{...}`.
pub use capacity_artifacts::pseudonym::{derive as derive_pseudonym, Domain};
pub use capacity_artifacts::submission_set::OperativeContext;
pub use capacity_verify::capacity_evidence::{
    assemble_evidence, verify_capacity_evidence, CapacityEvidence, CapacityVerdict, EvidenceError,
    EvidenceInputs, OperationKeyDisclosure, ProjectedAuthorization, ProjectedCommitment,
    StableIdentifiers,
};
pub use capacity_verify::holder_keyset::{HolderKeySet, OperationKey};
pub use capacity_verify::merkle;

// The node's builder: wrap N already-signed loose commitments (evidence) into a
// `submission-set/1`. Re-exported so the HTTP layer can assemble a set from a
// loose commitment the SDK sent (node-owns-submission-set: the SDK ships the
// signed `CapacityEvidence`; the node builds the transport set).
pub use submission_set_builder::{
    assemble_submission_set, default_windows, DefaultWindows, SubmissionMember,
};

// Settlement cable TYPES the node carries/packages (the verification_package
// embeds the `SettlementMaterial` the issuance service produces). Producing the
// settlement belongs to that service, not here.
pub use settlement::{SettlementAssemblyError, SettlementMaterial, SettlementReceipt};
pub use verification_package::{
    assemble_verification_package, PackageInputs, VerificationContext, VerificationPackage,
};

// Packaging lives in the protocol core: the shape a verifier consumes is
// contract, not something this crate defines on its own.
pub use capacity_artifacts::verification_package;
