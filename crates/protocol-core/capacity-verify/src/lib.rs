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

//! Zero-data capacity verification (and production).
//!
//! This crate consumes the closed-schema types of [`capacity_artifacts`] and
//! verifies the projected `capacity.evidence/1` offline (and produces it). The
//! cryptographic primitive is ML-DSA-65 (FIPS 204) under the active rules
//! domain `rules/2026-01`.
//!
//! Module map:
//! - [`manifest`]  — `system-manifest/1` resolver trait + the in-memory static resolver
//! - [`foundation`] — `system-foundation/1` verification and the resolver built on it
//! - [`mldsa`]     — ML-DSA-65 sign/verify wrapper
//! - [`composite`] / [`ecdsa_p256`] — the composite signature profile and its classical component
//! - [`capacity_evidence`] — the zero-data capacity-evidence offline verifier
//!   AND producer (`assemble_evidence`). The wire types live in
//!   `capacity-artifacts`; producer and verifier live here, in
//!   the same crate, so whoever submits and whoever checks run the
//!   SAME code — no producer/verifier drift.
//! - [`holder_keyset`] — the secret-bearing operation-key tree producer.
//!
//! A party that trusts the system domain's keys without holding them resolves
//! them through [`foundation::FoundationManifestResolver`], built from the
//! signed `system-foundation/1` statement the key ceremony emits.

pub mod capacity_evidence;
pub mod composite;
pub mod ecdsa_p256;
pub mod errors;
pub mod foundation;
pub mod holder_keyset;
pub mod manifest;
pub mod mldsa;

pub use capacity_evidence::{
    assemble_evidence, verify_capacity_evidence, CapacityVerdict, EvidenceError, EvidenceInputs,
    StableIdentifiers,
};
pub use holder_keyset::{HolderKeySet, OperationKey};
// The evidence wire types + the Merkle tree live in `capacity-artifacts`;
// re-exported so callers can reach them through `capacity_verify::{...}`.
pub use capacity_artifacts::capacity_evidence::{
    operation_key_leaf_hash, CapacityEvidence, OperationKeyDisclosure, ProjectedAuthorization,
    ProjectedCommitment, ZERO_DATA_PROFILE,
};
pub use capacity_artifacts::merkle;
pub use errors::{VerifyError, VerifyResult};
pub use foundation::{
    verify_system_foundation, FoundationError, FoundationManifestResolver, VerifiedFoundation,
};
pub use manifest::{
    derive_kid, ManifestError, ManifestResolver, ResolvedManifestEntry, StaticManifestResolver,
};
