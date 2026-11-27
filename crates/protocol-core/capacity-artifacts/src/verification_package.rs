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

//! `verification_package` assembly — the offline-verifiable envelope.
//!
//! The pure serializer for a `verification-package/1` package. It does NOT
//! verify, sign, settle, or touch the chain: it gathers artifacts produced
//! elsewhere into the one JSON object an offline verifier reads.
//!
//! ## Shape: one object, closed member set
//!
//! `verification-package/1` §9.4 and §22.1 fix the package as one JSON object
//! whose members are exactly `base_certificate` and `verification_context`
//! (always), `independence_proof`, `capacity_evidence`,
//! `commitment_inclusion_proof` and `settlement_material` (for `Independent`),
//! and an optional `settlement_reference` equal to the proof's `settlement_ref`.
//! There is no version, target or nesting member: a verifier refuses any other
//! member, so this struct is the whole format.
//!
//! ## Transport container, not a signed artifact
//!
//! The package carries already-signed artifacts; it is itself unsigned
//! transport. So, unlike [`crate::settlement`] (whose preimages are
//! insertion-ordered because their hash is load-bearing), the package needs no
//! signing-byte discipline. [`VerificationPackage::digest_hex`] is offered for
//! transport integrity / dedupe only, and uses JCS (RFC 8785) + SHA3-256 — the
//! same cross-language-deterministic discipline as
//! [`capacity_verify::capacity_evidence::CapacityEvidence::evidence_digest_hex`] — so a
//! Rust producer and a TS consumer agree on the digest regardless of struct
//! field order.
//!
//! ## Owned vs. opaque fields
//!
//! [`CapacityEvidence`] and [`CommitmentInclusionProof`] are types this crate
//! defines, so they are carried typed. The certificate, the proof and the
//! settlement material are produced elsewhere and reach the packager already
//! serialized, so `base_certificate`, `independence_proof` and
//! `settlement_material` are carried as opaque [`serde_json::Value`] transport —
//! the packager assembles them verbatim and never reinterprets their internals.

use serde::Serialize;
use serde_json::Value;
use sha3::{Digest, Sha3_256};

use crate::capacity_evidence::CapacityEvidence;
use crate::settlement::CommitmentInclusionProof;

/// The context object naming the rules version and system domain the package
/// is evaluated under (`verification-package/1` §9.4). Both fields are required,
/// and a verifier requires them to equal the certificate's signed payload and
/// the proof's (§13): a package whose context disagrees is rejected.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationContext {
    pub rules_version: String,
    pub system_id: String,
}

/// A `verification-package/1` package.
///
/// Field order follows the example of `verification-package/1` §15.2.1
/// (capacity precedes settlement); it is presentational only — member order in
/// a JSON object carries no meaning and the digest is taken over JCS.
///
/// The `Option` fields are what an `Independent` package carries
/// (`verification-package/1` §9.2): `capacity_evidence` (zero-data path),
/// `commitment_inclusion_proof` and `settlement_material`. A package without
/// them can be verified only as `Issued`. `settlement_reference` is optional
/// in every package.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationPackage {
    /// Opaque transport: the `base_certificate` the issuer produced. Every
    /// package carries it (`verification-package/1` §9.1).
    pub base_certificate: Value,

    /// Opaque transport: the `independence_proof` (proof model produced
    /// upstream). The packager never reinterprets its internals.
    pub independence_proof: Value,

    pub verification_context: VerificationContext,

    /// Zero-data capacity evidence (typed; defined in this crate). Present only on
    /// the zero-data path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity_evidence: Option<CapacityEvidence>,

    /// Per-commitment inclusion path `commitment → subtree_root` (typed). The
    /// verifier consumes this as its own field, beneath the leaf→settlement_root
    /// path inside `settlement_material`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_inclusion_proof: Option<CommitmentInclusionProof>,

    /// Opaque transport: the full `SettlementMaterial`. CERTCRYPT (the issuance
    /// service) PRODUCES it (`independence.proof/1 §10.6`); the node receives it
    /// via the issuance service and transports it VERBATIM, never reinterpreting
    /// its internals. Its validity does NOT rest on trusting the producer — the final
    /// offline verifier recomputes it. Hence opaque `Value`, like
    /// `base_certificate` / `independence_proof` — NOT a node-owned typed artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_material: Option<Value>,

    /// Optional copy of the proof's `settlement_ref` (`verification-package/1`
    /// §9.4). It carries no meaning of its own: a verifier requires it to equal
    /// the proof's value exactly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_reference: Option<String>,
}

/// Inputs to [`assemble_verification_package`]. Mirrors the owned/opaque split:
/// the caller hands typed material this crate defines and opaque transport for the
/// rest. The assembler does no validation — it gathers and shapes.
pub struct PackageInputs {
    pub base_certificate: Value,
    pub independence_proof: Value,
    pub rules_version: String,
    pub system_id: String,
    pub capacity_evidence: Option<CapacityEvidence>,
    pub commitment_inclusion_proof: Option<CommitmentInclusionProof>,
    /// Opaque transport (produced by the issuance service, received verbatim — see field doc
    /// on `VerificationPackage::settlement_material`).
    pub settlement_material: Option<Value>,
    pub settlement_reference: Option<String>,
}

impl VerificationPackage {
    /// Serialize to canonical JCS (RFC 8785) bytes. Sorted keys, so a TS
    /// consumer reading the same logical content agrees byte-for-byte.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_jcs::to_vec(self)
    }

    /// Pretty-printed (insertion-ordered) JSON, for fixtures and human reading.
    /// NOT canonical — use [`to_canonical_bytes`](Self::to_canonical_bytes) when
    /// a deterministic digest is needed.
    pub fn to_pretty_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// `package_digest` of `verification-package/1` §22.4: `SHA3-256(JCS(self))`,
    /// lowercase hex. For transport integrity and dedupe only — the package is
    /// unsigned transport, so this is not a security boundary.
    pub fn digest_hex(&self) -> Result<String, serde_json::Error> {
        let bytes = self.to_canonical_bytes()?;
        Ok(hex::encode(Sha3_256::digest(&bytes)))
    }
}

/// Pure assembler: gather inputs into the `verification-package/1` object.
/// No verification, no signing, no chain access.
pub fn assemble_verification_package(inputs: PackageInputs) -> VerificationPackage {
    VerificationPackage {
        base_certificate: inputs.base_certificate,
        independence_proof: inputs.independence_proof,
        verification_context: VerificationContext {
            rules_version: inputs.rules_version,
            system_id: inputs.system_id,
        },
        capacity_evidence: inputs.capacity_evidence,
        commitment_inclusion_proof: inputs.commitment_inclusion_proof,
        settlement_material: inputs.settlement_material,
        settlement_reference: inputs.settlement_reference,
    }
}
