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

//! Wire-format types for `submission-set/1` artifacts.
//!
//! Carries the closed shape a transporting node canonicalizes when closing a
//! submission set of `independent_intent` certificates. Each
//! `SubmissionSetCertificateV1` carries the zero-data `CapacityEvidence` (the
//! projected, unlinkable capacity proof the offline verifier checks) plus an
//! `operative` context — `holder_id`/`pool_id` in clear, node→issuance-service-only, so
//! the service can attribute the consumed capacity. The `operative` context never reaches the offline
//! verifier; the evidence carries only pseudonyms. Each evidence embeds its own
//! Level-2 `ProjectedAuthorization` (anchored by the system-domain Level-1
//! signature) — there is no top-level authorization slice.
//!
//! Determinism: `submission_set_id = sha3_256_hex(JCS(set without submission_set_id))`.
//! Mirrors the two-pass discipline of `commitment_id`, `authorization_id`, and
//! `proof_id`. The offline capacity-evidence verifier (Levels 1–3, membership,
//! pseudonym bindings) lives in `capacity-verify` and consumes the types here.

use crate::canonical::{canonical_digest_hex, canonicalize, is_lower_hex_64};
use crate::capacity_evidence::CapacityEvidence;
use crate::errors::ArtifactError;
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};

pub const SUBMISSION_SET_VERSION: &str = "submission-set/1";
pub const SYSTEM_ID_ACTIVE: &str = "certcrypt";

/// Maximum number of members a conforming `submission-set/1` may contain
/// (submission-set/1 §8.1). Normative, fail-closed protocol constant: a set with
/// more members is malformed at the set level and MUST be rejected as a whole,
/// before any per-member evaluation or capacity consumption. The single Rust
/// source of truth — the assembler and the submit endpoint both reference it,
/// and the SDKs mirror it as `MAX_SUBMISSION_SET_MEMBERS`. It is pinned by the
/// conformance contract (`fixtures/primitives/submission-set-limits`).
///
/// The value is **64**, deliberately below the count at which a zero-data set
/// (~14 KiB per member: ML-DSA-65 evidence + inclusion proof) would approach the
/// request-body limits HTTP servers commonly default to (2 MiB). 64 (~0.9 MiB)
/// keeps the cap reachable end-to-end with margin for per-member evidence growth. Per-member size is independent of subject count / collection
/// cardinality (the set carries evidence digests, not base certs or subjects;
/// see submission-set/1 §8.1), so the member cap bounds the payload directly.
pub const MAX_SUBMISSION_SET_MEMBERS: usize = 64;

/// Closed-schema `submission-set/1` artifact. Field order in `serde` is the
/// declaration order, but canonical bytes are produced via JCS (RFC 8785),
/// which sorts members lexicographically.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmissionSetV1 {
    pub schema: String,
    pub system_id: String,
    pub rules_version: String,
    pub system_root_fingerprint: String,
    pub submission_set_id: String,
    pub closure_time: DateTime<Utc>,
    pub certificates: Vec<SubmissionSetCertificateV1>,
}

/// The canonical member: exactly these two fields (submission-set/1 §7.1).
///
/// Both are covered by the `submission_set_id` digest, so the member shape and
/// the identifier are fixed together — `deny_unknown_fields` is what makes that
/// identifier reproducible across implementations rather than a per-producer
/// choice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmissionSetCertificateV1 {
    pub capacity_evidence: CapacityEvidence,
    pub operative: OperativeContext,
}

/// Node→issuance-service operative context for one certificate: the stable
/// identifiers the issuance service needs to attribute the consumed capacity
/// `(holder, pool)`. In clear between node and issuance service only — it is part of the transport set (and so of
/// `submission_set_id`, mirroring the SDK) but never reaches the offline
/// verifier, which receives only the pseudonymized `CapacityEvidence`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperativeContext {
    pub holder_id: String,
    pub pool_id: String,
}

/// Same shape minus `submission_set_id`. Used for the deterministic-id pass:
/// SHA3-256 of the JCS canonicalization of the set with `submission_set_id`
/// absent.
#[derive(Debug, Clone, Serialize)]
struct SubmissionSetV1NoId<'a> {
    schema: &'a str,
    system_id: &'a str,
    rules_version: &'a str,
    system_root_fingerprint: &'a str,
    closure_time: &'a DateTime<Utc>,
    certificates: &'a [SubmissionSetCertificateV1],
}

impl SubmissionSetV1 {
    /// Compute the deterministic `submission_set_id` from canonical submission-set bytes (with
    /// `submission_set_id` removed). Recomputed offline by the verifier.
    pub fn compute_submission_set_id(
        schema: &str,
        system_id: &str,
        rules_version: &str,
        system_root_fingerprint: &str,
        closure_time: &DateTime<Utc>,
        certificates: &[SubmissionSetCertificateV1],
    ) -> Result<String, ArtifactError> {
        let view = SubmissionSetV1NoId {
            schema,
            system_id,
            rules_version,
            system_root_fingerprint,
            closure_time,
            certificates,
        };
        canonical_digest_hex(&view)
    }

    /// Recompute `submission_set_id` from the carried set. Callers compare against
    /// `self.submission_set_id` and fail closed on divergence.
    pub fn recompute_submission_set_id(&self) -> Result<String, ArtifactError> {
        let view = SubmissionSetV1NoId {
            schema: &self.schema,
            system_id: &self.system_id,
            rules_version: &self.rules_version,
            system_root_fingerprint: &self.system_root_fingerprint,
            closure_time: &self.closure_time,
            certificates: &self.certificates,
        };
        canonical_digest_hex(&view)
    }

    /// Full canonical bytes of the submission set. What gets persisted,
    /// transported, and hashed for the `submission_set_digest` that a submission
    /// record and `independence_proof/1` both carry.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        canonicalize(self)
    }

    /// Structural invariants. Cryptographic chain verification, scope checks,
    /// and temporal checks against expires_at live in higher-level crates.
    pub fn validate_structure(&self) -> Result<(), ArtifactError> {
        if self.schema != SUBMISSION_SET_VERSION {
            return Err(ArtifactError::InvalidField {
                field: "schema",
                reason: format!("expected {SUBMISSION_SET_VERSION:?}, got {:?}", self.schema),
            });
        }
        // system_id is HARDWIRED to SYSTEM_ID_ACTIVE on purpose. The TRUST ANCHOR
        // (the system_root_fingerprint + the Level-1 keys, resolved from a manifest)
        // is protocol-driven — configurable, so the software can serve any
        // system-domain. But the NAME is a brand label, not a trust input (the
        // fingerprint anchors it, since system_id is inside the manifest preimage).
        // Keeping the name compiled-in adds a cheap brand/supply-chain barrier: a fork
        // that wants a different name must RECOMPILE — the official signed binary
        // always says "certcrypt". This does NOT weaken protocol-drivenness (that
        // lives in the fingerprint/manifest) and costs no real neutrality (a serious
        // fork recompiles anyway; a lazy impostor cannot just set an env var).
        if self.system_id != SYSTEM_ID_ACTIVE {
            return Err(ArtifactError::InvalidField {
                field: "system_id",
                reason: format!("expected {SYSTEM_ID_ACTIVE:?}, got {:?}", self.system_id),
            });
        }
        if self.rules_version.is_empty() || !self.rules_version.is_ascii() {
            return Err(ArtifactError::InvalidField {
                field: "rules_version",
                reason: "must be non-empty ASCII".into(),
            });
        }
        if !is_lower_hex_64(&self.system_root_fingerprint) {
            return Err(ArtifactError::InvalidField {
                field: "system_root_fingerprint",
                reason: "must be 64 lowercase hex".into(),
            });
        }
        if !is_lower_hex_64(&self.submission_set_id) {
            return Err(ArtifactError::InvalidField {
                field: "submission_set_id",
                reason: "must be 64 lowercase hex".into(),
            });
        }
        // closure_time is the canonical submission-set close
        // timestamp the verifier reproduces against expires_at. Reject any
        // sub-second precision so the canonical bytes are deterministic across
        // implementations (some serializers strip trailing zeros).
        if self.closure_time.nanosecond() != 0 {
            return Err(ArtifactError::InvalidField {
                field: "closure_time",
                reason: "must be RFC 3339 with second precision (no fractional seconds)".into(),
            });
        }
        if self.certificates.is_empty() {
            return Err(ArtifactError::InvalidField {
                field: "certificates",
                reason: "must contain at least one certificate".into(),
            });
        }
        if self.certificates.len() > MAX_SUBMISSION_SET_MEMBERS {
            return Err(ArtifactError::InvalidField {
                field: "certificates",
                reason: format!(
                    "submission set exceeds the maximum of {MAX_SUBMISSION_SET_MEMBERS} members \
                     (got {}); the set is rejected as a whole (submission-set/1 §8.1)",
                    self.certificates.len()
                ),
            });
        }

        // Each certificate: an operative context with non-empty holder_id/pool_id,
        // and a capacity_evidence whose projected fields
        // agree with the set's rules-domain. Cryptographic verification of the
        // evidence (Level-1 anchor, leaf membership, Level-3 signature,
        // pseudonym bindings) is the verifier's job (capacity-verify) — here we
        // only check structural agreement, never trust.
        for cert in &self.certificates {
            if cert.operative.holder_id.is_empty() || !cert.operative.holder_id.is_ascii() {
                return Err(ArtifactError::InvalidField {
                    field: "certificates[].operative.holder_id",
                    reason: "must be non-empty ASCII".into(),
                });
            }
            if cert.operative.pool_id.is_empty() || !cert.operative.pool_id.is_ascii() {
                return Err(ArtifactError::InvalidField {
                    field: "certificates[].operative.pool_id",
                    reason: "must be non-empty ASCII".into(),
                });
            }

            let pa = &cert.capacity_evidence.projected_authorization;
            let pc = &cert.capacity_evidence.projected_commitment;
            if pc.system_root_fingerprint != self.system_root_fingerprint
                || pa.system_root_fingerprint != self.system_root_fingerprint
            {
                return Err(ArtifactError::InvalidField {
                    field: "certificates[].capacity_evidence.system_root_fingerprint",
                    reason:
                        "projected commitment/authorization must equal set.system_root_fingerprint"
                            .into(),
                });
            }
            if pc.rules_version != self.rules_version || pa.rules_version != self.rules_version {
                return Err(ArtifactError::InvalidField {
                    field: "certificates[].capacity_evidence.rules_version",
                    reason: "projected commitment/authorization must equal set.rules_version"
                        .into(),
                });
            }
        }

        let recomputed = self.recompute_submission_set_id()?;
        if recomputed != self.submission_set_id {
            return Err(ArtifactError::CommitmentIdMismatch {
                declared: self.submission_set_id.clone(),
                recomputed,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capacity_evidence::{
        CapacityEvidence, OperationKeyDisclosure, ProjectedAuthorization, ProjectedCommitment,
        ZERO_DATA_PROFILE,
    };
    use crate::capacity_holder_authorization::Level1AuthorizationBinding;

    const RULES: &str = "rules/conformance";
    const SRF: &str = "abababababababababababababababababababababababababababababababab";

    // ---- zero-data evidence fixtures (hand-built; no signing) -------------
    //
    // `validate_structure` is STRUCTURAL
    // logic — they do not verify signatures (that is the verifier's job, in
    // capacity-verify, exercised by its own tests and the published goldens). So
    // these tests build a structurally-complete `CapacityEvidence` by hand,
    // with placeholder signature bytes, to exercise the contract surface in
    // this crate. capacity-artifacts cannot depend on the producer
    // (capacity-verify) without inverting the crate hierarchy.

    fn binding(root: &str) -> Level1AuthorizationBinding {
        Level1AuthorizationBinding {
            system_id: SYSTEM_ID_ACTIVE.into(),
            rules_version: RULES.into(),
            system_root_fingerprint: SRF.into(),
            authorized_role: "capacity_commitment_holder".into(),
            authorization_issuer_kid: "system-domain-kid-1".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
            holder_key_set_root: root.into(),
        }
    }

    /// A structurally-complete evidence. `root` distinguishes authorizations
    /// (the zero-data leaf-grouping anchor); `cert_digest` and `salt` vary the
    /// evidence digest so two members get distinct `capacity_commitment_id`s.
    fn evidence(root: &str, cert_digest: &str, salt_hex: &str) -> CapacityEvidence {
        let projected_authorization = ProjectedAuthorization {
            system_id: SYSTEM_ID_ACTIVE.into(),
            rules_version: RULES.into(),
            system_root_fingerprint: SRF.into(),
            authorized_role: "capacity_commitment_holder".into(),
            authorization_issuer_kid: "system-domain-kid-1".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
            holder_key_set_root: root.into(),
            level1_binding: binding(root),
            level1_signature: crate::composite_sig::CompositeSignatureWire::and(
                crate::composite_sig::PROFILE_ED25519_MLDSA65,
                vec![
                    crate::composite_sig::ComponentSignature::ed25519("AAA=".into()),
                    crate::composite_sig::ComponentSignature::mldsa65("AAA=".into()),
                ],
            ),
            authorization_pseudonym: "aa".repeat(32),
            holder_pseudonym: "bb".repeat(32),
        };
        let projected_commitment = ProjectedCommitment {
            commitment_version: "capacity.commitment/1".into(),
            system_id: SYSTEM_ID_ACTIVE.into(),
            system_root_fingerprint: SRF.into(),
            rules_version: RULES.into(),
            authorization_pseudonym: "aa".repeat(32),
            holder_pseudonym: "bb".repeat(32),
            pool_pseudonym: "cc".repeat(32),
            certificate_commitment_digest: cert_digest.into(),
            consumed_quantity: "1".into(),
            declared_effective_units: "1".into(),
            issued_at: "2026-05-09T12:00:00Z".into(),
            expires_at: "2026-05-09T12:15:00Z".into(),
        };
        CapacityEvidence {
            profile: ZERO_DATA_PROFILE.into(),
            operation_salt_hex: salt_hex.into(),
            projected_authorization,
            projected_commitment,
            operation_key: OperationKeyDisclosure {
                leaf_index: 0,
                public_key_b64: "AAA=".into(),
                inclusion_proof: vec![],
                tree_size: 1,
            },
            commitment_signature_b64: "AAA=".into(),
        }
    }

    fn cert(ev: CapacityEvidence) -> SubmissionSetCertificateV1 {
        SubmissionSetCertificateV1 {
            capacity_evidence: ev,
            operative: OperativeContext {
                holder_id: "holder:6ba7b811-9dad-41d4-a716-446655440000".into(),
                pool_id: "default".into(),
            },
        }
    }

    fn sample_set_with(certs: Vec<SubmissionSetCertificateV1>) -> SubmissionSetV1 {
        let closure: DateTime<Utc> = "2026-05-09T12:05:00Z".parse().unwrap();
        let submission_set_id = SubmissionSetV1::compute_submission_set_id(
            SUBMISSION_SET_VERSION,
            SYSTEM_ID_ACTIVE,
            RULES,
            SRF,
            &closure,
            &certs,
        )
        .unwrap();
        SubmissionSetV1 {
            schema: SUBMISSION_SET_VERSION.into(),
            system_id: SYSTEM_ID_ACTIVE.into(),
            rules_version: RULES.into(),
            system_root_fingerprint: SRF.into(),
            submission_set_id,
            closure_time: closure,
            certificates: certs,
        }
    }

    fn well_formed_set() -> SubmissionSetV1 {
        sample_set_with(vec![cert(evidence(
            &"11".repeat(32),
            &"ef".repeat(32),
            &"aa".repeat(8),
        ))])
    }

    #[test]
    fn submission_set_id_is_deterministic() {
        let a = well_formed_set();
        let b = well_formed_set();
        assert_eq!(a.submission_set_id, b.submission_set_id);
        assert_eq!(
            a.recompute_submission_set_id().unwrap(),
            a.submission_set_id
        );
    }

    #[test]
    fn validate_structure_accepts_well_formed() {
        well_formed_set()
            .validate_structure()
            .expect("well-formed set validates");
    }

    #[test]
    fn validate_structure_rejects_empty_certificates() {
        let mut s = well_formed_set();
        s.certificates.clear();
        // The empty-certificates check fires before the id recompute.
        let err = s.validate_structure().unwrap_err();
        assert!(
            matches!(err, ArtifactError::InvalidField { field, .. } if field == "certificates")
        );
    }

    #[test]
    fn validate_structure_rejects_over_cardinality_set() {
        // submission-set/1 §8.1: > MAX_SUBMISSION_SET_MEMBERS is rejected as a whole.
        let mut s = well_formed_set();
        let proto = s.certificates[0].clone();
        s.certificates = (0..=MAX_SUBMISSION_SET_MEMBERS)
            .map(|_| proto.clone())
            .collect();
        assert_eq!(s.certificates.len(), MAX_SUBMISSION_SET_MEMBERS + 1);
        let err = s.validate_structure().unwrap_err();
        assert!(
            matches!(err, ArtifactError::InvalidField { field, .. } if field == "certificates")
        );
    }

    #[test]
    fn validate_structure_accepts_exactly_max_members() {
        // Exactly MAX is within bound (the per-member checks still run; this set's
        // members are clones of a well-formed one with distinct ids).
        let mut s = well_formed_set();
        let proto = s.certificates[0].clone();
        s.certificates = (0..MAX_SUBMISSION_SET_MEMBERS)
            .map(|_| proto.clone())
            .collect();
        s.submission_set_id = s.recompute_submission_set_id().unwrap();
        assert!(s.validate_structure().is_ok());
    }

    #[test]
    fn validate_structure_rejects_empty_operative_ids() {
        let mut s = well_formed_set();
        s.certificates[0].operative.holder_id = String::new();
        s.submission_set_id = s.recompute_submission_set_id().unwrap();
        let err = s.validate_structure().unwrap_err();
        assert!(matches!(err, ArtifactError::InvalidField { field, .. }
            if field == "certificates[].operative.holder_id"));
    }

    #[test]
    fn validate_structure_rejects_mismatched_system_root_fingerprint() {
        let mut s = well_formed_set();
        s.certificates[0]
            .capacity_evidence
            .projected_commitment
            .system_root_fingerprint = "cd".repeat(32);
        s.submission_set_id = s.recompute_submission_set_id().unwrap();
        let err = s.validate_structure().unwrap_err();
        assert!(matches!(err, ArtifactError::InvalidField { field, .. }
            if field == "certificates[].capacity_evidence.system_root_fingerprint"));
    }

    #[test]
    fn validate_structure_rejects_mismatched_rules_version() {
        let mut s = well_formed_set();
        s.certificates[0]
            .capacity_evidence
            .projected_commitment
            .rules_version = "rules/2099-12".into();
        s.submission_set_id = s.recompute_submission_set_id().unwrap();
        let err = s.validate_structure().unwrap_err();
        assert!(matches!(err, ArtifactError::InvalidField { field, .. }
            if field == "certificates[].capacity_evidence.rules_version"));
    }

    #[test]
    fn validate_structure_rejects_tampered_submission_set_id() {
        let mut s = well_formed_set();
        s.submission_set_id = "00".repeat(32);
        let err = s.validate_structure().unwrap_err();
        assert!(matches!(err, ArtifactError::CommitmentIdMismatch { .. }));
    }

    #[test]
    fn validate_structure_rejects_fractional_seconds_in_closure_time() {
        let closure: DateTime<Utc> = "2026-05-09T12:05:00.123456789Z".parse().unwrap();
        let c = cert(evidence(
            &"11".repeat(32),
            &"ef".repeat(32),
            &"aa".repeat(8),
        ));
        let submission_set_id = SubmissionSetV1::compute_submission_set_id(
            SUBMISSION_SET_VERSION,
            SYSTEM_ID_ACTIVE,
            RULES,
            SRF,
            &closure,
            std::slice::from_ref(&c),
        )
        .unwrap();
        let s = SubmissionSetV1 {
            schema: SUBMISSION_SET_VERSION.into(),
            system_id: SYSTEM_ID_ACTIVE.into(),
            rules_version: RULES.into(),
            system_root_fingerprint: SRF.into(),
            submission_set_id,
            closure_time: closure,
            certificates: vec![c],
        };
        let err = s.validate_structure().unwrap_err();
        assert!(
            matches!(err, ArtifactError::InvalidField { field, .. } if field == "closure_time")
        );
    }

    #[test]
    fn canonical_round_trip() {
        let s = well_formed_set();
        let bytes = s.canonical_bytes().unwrap();
        let restored: SubmissionSetV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, s);
    }

    #[test]
    fn deny_unknown_fields_at_top_level() {
        let s = well_formed_set();
        let mut v = serde_json::to_value(&s).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("rogue".into(), serde_json::json!(1));
        let err = serde_json::from_value::<SubmissionSetV1>(v).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }
}
