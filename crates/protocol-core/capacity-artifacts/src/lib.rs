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

//! CERTCRYPT capacity-artifact wire-format types.
//!
//! Carries the closed-schema Rust representations and deterministic-digest
//! helpers for the zero-data capacity artifacts:
//!
//! - [`capacity_evidence::CapacityEvidence`] — the projected, unlinkable proof
//!   the holder signs (Level-3 leaf) and CERTCRYPT anchors (Level-1 binding)
//! - [`capacity_holder_authorization::Level1AuthorizationBinding`] — the
//!   system-domain-signed Level-1 anchor over the `holder_key_set_root`
//! - [`submission_set::SubmissionSetV1`] — the transport set of evidence members
//!
//! The `independence.proof/1` artifact is not typed here: the fixation service
//! composes it, and it lists the consumed commitments by the `commitment_id`
//! these types define.
//!
//! Signature-chain verification, transport and persistence live in
//! higher-level crates and consume the types here.

pub mod canonical;
pub mod capacity_commitment;
pub mod capacity_evidence;
pub mod capacity_holder_authorization;
pub mod composite_sig;
pub mod errors;
pub mod merkle;
pub mod operator_domain_binding;
pub mod operator_recognition;
pub mod pseudonym;
pub mod settlement;
pub mod submission_set;
pub mod verification_package;

pub use canonical::{canonical_digest_hex, canonicalize, is_lower_hex_64, sha3_256_hex};
pub use capacity_evidence::{
    operation_key_leaf_hash, CapacityEvidence, OperationKeyDisclosure, ProjectedAuthorization,
    ProjectedCommitment, ZERO_DATA_PROFILE,
};
pub use capacity_holder_authorization::Level1AuthorizationBinding;
pub use errors::ArtifactError;
pub use operator_recognition::{
    derive_operator_id, OperatorRecognitionCredentialV1, RecognitionInputs, RecognitionIssuer,
    RecognitionSignature,
};
pub use submission_set::{SubmissionSetCertificateV1, SubmissionSetV1, SUBMISSION_SET_VERSION};
