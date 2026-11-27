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

//! Assemble a zero-data `submission-set/1` for a real contract — Model A (the
//! issuer signs the emission; the node only assembles and submits).
//!
//! Under the zero-data profile each certificate carries a [`CapacityEvidence`]
//! — the projected, unlinkable capacity proof — instead of a cleartext
//! `capacity.commitment/1`. The evidence already embeds, signed:
//!
//!   - Level-1 (authorization): the SYSTEM-DOMAIN's `Level1AuthorizationBinding`
//!     over the holder's `holder_key_set_root` (the trust anchor). This is NOT
//!     the emission; it authorizes the holder's operation-key tree.
//!
//!   - Level-3 (commitment): the ISSUER's emission, signed with a per-operation
//!     LEAF key of that tree. The node MUST NOT hold or fabricate this key:
//!     emission is the issuer's act, the node only transports and anchors it
//!     (no-custody doctrine).
//!
//! Accordingly this module exposes:
//!   - [`build_member_evidence`] — the producer that assembles one member's
//!     [`CapacityEvidence`]. Conceptually run BY THE ISSUER with the issuer's
//!     operation-key secret + the system-domain Level-1 secret. Exposed here as
//!     a reusable primitive (the issuer's SDK or issuer application produces it
//!     in production); it wraps the single shared producer [`assemble_evidence`] so there is no
//!     second producer to diverge.
//!   - [`assemble_submission_set`] — the NODE's only job: take N already-signed
//!     evidence members and assemble the submission set (one settlement leaf).
//!     The node touches no emission key here.
//!
//! All crypto reuses the shared producer/verifier in `capacity-verify` verbatim
//! (no crypto fork): the same code the online submit path verifies against.

use capacity_artifacts::submission_set::{
    OperativeContext, SubmissionSetCertificateV1, SubmissionSetV1, SUBMISSION_SET_VERSION,
    SYSTEM_ID_ACTIVE,
};
use capacity_verify::capacity_evidence::CapacityEvidence;
use capacity_verify::{
    assemble_evidence, EvidenceError, EvidenceInputs, HolderKeySet, StableIdentifiers,
};
use chrono::{DateTime, Duration, Timelike, Utc};

/// Inputs to produce one member's zero-data [`CapacityEvidence`]. The issuer
/// controls the emission; the system-domain Level-1 secret authorizes the
/// holder's operation-key tree root. Both secrets are inputs here so the
/// produced evidence carries the verifiable anchor — in production the issuer's
/// SDK holds the operation-key secrets and the system domain signs the Level-1
/// binding.
pub struct MemberEvidenceParams<'a> {
    pub system_root_fingerprint: String,
    pub rules_version: String,
    pub authorized_role: String,
    pub authorization_issuer_kid: String,
    pub valid_from: String,
    pub valid_until: String,
    pub certificate_commitment_digest: String,
    pub consumed_quantity: String,
    /// Issuer-declared per-subject effective units (`submission-set/1 §13.2`):
    /// non-collection subject → `"1"`, collection → its `declared_cardinality`.
    /// Bound into the signed projected commitment (the value the `cost_commitment`
    /// preimage commits to); distinct from `consumed_quantity`.
    pub declared_effective_units: String,
    pub issued_at: String,
    pub expires_at: String,
    /// Stable identifiers projected to pseudonyms in the evidence (never travel
    /// in clear). `holder_id`/`pool_id` are also carried OUT-OF-BAND in the
    /// member's [`OperativeContext`] (node→issuance-service cleartext), so the service can attribute the consumed capacity.
    pub stable: StableIdentifiers,
    /// The holder's authorized operation-key tree.
    pub key_set: &'a HolderKeySet,
    /// Which leaf signs this commitment. MUST NOT be reused across commitments.
    pub leaf_index: usize,
    /// Fresh public per-operation salt. MUST be unique per operation.
    pub operation_salt: Vec<u8>,
    /// System-domain (Level-1) secret key authorizing the key-set root.
    pub system_domain_secret_key: &'a [u8],
    /// 32-byte seed of the classical (ECDSA P-256) component of the composite
    /// Level-1 key (`composite-signature/1`).
    pub system_domain_classical_seed: &'a [u8; 32],
}

/// Produce one member's zero-data capacity evidence. Thin wrapper over the
/// shared [`assemble_evidence`] producer — there is exactly one producer for the
/// issuance service and the node.
pub fn build_member_evidence(
    p: &MemberEvidenceParams<'_>,
) -> Result<CapacityEvidence, EvidenceError> {
    let inputs = EvidenceInputs {
        system_id: SYSTEM_ID_ACTIVE.to_string(),
        system_root_fingerprint: p.system_root_fingerprint.clone(),
        rules_version: p.rules_version.clone(),
        authorized_role: p.authorized_role.clone(),
        authorization_issuer_kid: p.authorization_issuer_kid.clone(),
        valid_from: p.valid_from.clone(),
        valid_until: p.valid_until.clone(),
        certificate_commitment_digest: p.certificate_commitment_digest.clone(),
        consumed_quantity: p.consumed_quantity.clone(),
        declared_effective_units: p.declared_effective_units.clone(),
        issued_at: p.issued_at.clone(),
        expires_at: p.expires_at.clone(),
        stable: p.stable.clone(),
        key_set: p.key_set,
        leaf_index: p.leaf_index,
        operation_salt: p.operation_salt.clone(),
        system_domain_secret_key: p.system_domain_secret_key,
        system_domain_classical_seed: p.system_domain_classical_seed,
    };
    assemble_evidence(&inputs)
}

/// One already-signed member of a submission set: the issuer's signed zero-data
/// [`CapacityEvidence`] (the emission, projected) and the node→issuance-service-only
/// [`OperativeContext`] (cleartext `holder_id`/`pool_id` for capacity attribution; never
/// reaches the offline verifier). These two fields are the canonical member
/// (submission-set/1 §7.1). The node never holds the key that signed the evidence.
#[derive(Clone)]
pub struct SubmissionMember {
    pub capacity_evidence: CapacityEvidence,
    pub operative: OperativeContext,
}

/// The NODE's only job: assemble a submission set (one settlement leaf) from N
/// already-signed zero-data evidence members. The node holds NO emission key
/// here.
///
/// Under `submission-set/1` the set's accepted subset forms one settlement leaf,
/// so every member MUST belong to the SAME capacity authorization (spec §8.3).
/// In the zero-data profile the stable `issuer_scope` / `holder_authorization_ref`
/// are projected away, so the leaf-grouping invariant is keyed off the projected
/// authorization that every member of one authorization shares verbatim: the
/// system-domain-signed `holder_key_set_root` + `authorization_issuer_kid`.
/// Members that differ belong in distinct leaves and MUST be assembled as
/// distinct sets. This is the node's own construction hygiene — NOT a trust
/// check: the issuance service re-derives the leaf from the cryptographically-accepted subset
/// and re-verifies every member's evidence regardless of what the node claims
/// (verify, don't trust). The hygiene here only avoids spending a round-trip
/// on a set the node itself built malformed:
///   - the set MUST be non-empty (a leaf with zero members is meaningless);
///   - all members MUST agree on `holder_key_set_root` + `authorization_issuer_kid`
///     (the leaf is bound to exactly one capacity authorization);
///   - all members MUST agree on the set's `rules_version` + `system_root_fingerprint`.
pub fn assemble_submission_set(
    members: Vec<SubmissionMember>,
    rules_version: &str,
    system_root_fingerprint: &str,
    closure_time: DateTime<Utc>,
) -> Result<SubmissionSetV1, String> {
    if members.is_empty() {
        return Err("submission set is empty: a settlement leaf needs at least one member".into());
    }
    // Set cardinality bound (submission-set/1 §8.1): refuse to assemble an
    // over-cardinality set. The node is the accumulation point under
    // the node owns the submission set, so this is the producer-side fail-fast;
    // the issuance service's submit endpoint enforces the same bound independently (fail-closed).
    if members.len() > capacity_artifacts::submission_set::MAX_SUBMISSION_SET_MEMBERS {
        return Err(format!(
            "submission set exceeds the maximum of {} members (got {}); refuse to assemble \
             (submission-set/1 §8.1)",
            capacity_artifacts::submission_set::MAX_SUBMISSION_SET_MEMBERS,
            members.len()
        ));
    }

    // Leaf-grouping hygiene (the node's own construction invariant, §8.3). The
    // first member fixes the leaf's authorization anchor; every other member
    // must match it.
    let first_pa = &members[0].capacity_evidence.projected_authorization;
    let leaf_root = first_pa.holder_key_set_root.clone();
    let leaf_issuer_kid = first_pa.authorization_issuer_kid.clone();
    for (index, m) in members.iter().enumerate() {
        let pa = &m.capacity_evidence.projected_authorization;
        if pa.holder_key_set_root != leaf_root || pa.authorization_issuer_kid != leaf_issuer_kid {
            return Err(format!(
                "submission set mixes capacity authorizations in one leaf \
                 (member at index {} binds a different holder_key_set_root/authorization_issuer_kid; \
                 members of distinct authorizations MUST form distinct sets, §9.3)",
                index
            ));
        }
        if pa.rules_version != rules_version
            || pa.system_root_fingerprint != system_root_fingerprint
        {
            return Err(format!(
                "member at index {} evidence disagrees with the set's rules_version / \
                 system_root_fingerprint",
                index
            ));
        }
    }

    let certs: Vec<SubmissionSetCertificateV1> = members
        .into_iter()
        .map(|m| SubmissionSetCertificateV1 {
            capacity_evidence: m.capacity_evidence,
            operative: m.operative,
        })
        .collect();

    let submission_set_id = SubmissionSetV1::compute_submission_set_id(
        SUBMISSION_SET_VERSION,
        SYSTEM_ID_ACTIVE,
        rules_version,
        system_root_fingerprint,
        &closure_time,
        &certs,
    )
    .map_err(|e| format!("compute submission_set_id: {e}"))?;

    Ok(SubmissionSetV1 {
        schema: SUBMISSION_SET_VERSION.into(),
        system_id: SYSTEM_ID_ACTIVE.into(),
        rules_version: rules_version.to_string(),
        system_root_fingerprint: system_root_fingerprint.to_string(),
        submission_set_id,
        closure_time,
        certificates: certs,
    })
}

/// The five timestamps a submission set needs, each under its own name.
///
/// Named fields rather than a tuple: five values of the same type in positions
/// can be swapped and still compile and run, and the failure would surface not
/// as a type error but as a certificate whose validity window is silently wrong.
/// Named fields make that swap impossible to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultWindows {
    /// When the set was closed. The issuance service requires SECOND precision.
    pub closure_time: DateTime<Utc>,
    /// Start of the certificate's validity window.
    pub valid_from: DateTime<Utc>,
    /// End of it.
    pub valid_until: DateTime<Utc>,
    /// When the certificate claims to have been issued.
    pub issued_at: DateTime<Utc>,
    /// When it stops being accepted.
    pub expires_at: DateTime<Utc>,
}

/// Convenience: sensible default validity windows for a dev submission set built "now".
/// `now` is passed in (the caller supplies `Utc::now()`); avoids hiding a clock
/// read inside the builder. Truncates sub-second precision (the issuance service requires
/// closure_time at SECOND precision; truncating everything keeps the
/// signed bytes consistent).
pub fn default_windows(now: DateTime<Utc>) -> DefaultWindows {
    let now = now
        .with_nanosecond(0)
        .expect("nanosecond=0 is always valid");
    DefaultWindows {
        closure_time: now,
        valid_from: now - Duration::days(1),
        valid_until: now + Duration::days(3650),
        issued_at: now - Duration::minutes(5),
        expires_at: now + Duration::days(365),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capacity_verify::mldsa;
    use chrono::TimeZone;

    const SRF: &str = "abababababababababababababababababababababababababababababababab";
    const RULES: &str = "rules/conformance";

    fn windows() -> (DateTime<Utc>, DateTime<Utc>) {
        let closure = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2027, 6, 1, 0, 0, 0).unwrap();
        (closure, expires)
    }

    /// Build N zero-data members under ONE holder key set + ONE system-domain
    /// key (so they share the same authorization anchor and form one leaf). Each
    /// member signs with a distinct leaf (non-reuse) and a fresh salt.
    fn members_n(n: usize, sd_sk: &[u8], key_set: &HolderKeySet) -> Vec<SubmissionMember> {
        (0..n)
            .map(|i| {
                let ev = build_member_evidence(&MemberEvidenceParams {
                    system_root_fingerprint: SRF.into(),
                    rules_version: RULES.into(),
                    authorized_role: "capacity_commitment_holder".into(),
                    authorization_issuer_kid: "system-domain-kid-1".into(),
                    valid_from: "2026-01-01T00:00:00Z".into(),
                    valid_until: "2027-01-01T00:00:00Z".into(),
                    certificate_commitment_digest: "ef".repeat(32),
                    consumed_quantity: "1".into(),
                    declared_effective_units: "1".into(),
                    issued_at: "2026-05-09T12:00:00Z".into(),
                    expires_at: "2026-05-09T12:15:00Z".into(),
                    stable: StableIdentifiers {
                        holder_id: "holder:example".into(),
                        pool_id: "pool:default".into(),
                        authorization_id: "auth:abc123".into(),
                    },
                    key_set,
                    leaf_index: i,
                    operation_salt: format!("op-salt-{i}").into_bytes(),
                    system_domain_secret_key: sd_sk,
                    system_domain_classical_seed: &[0x33u8; 32],
                })
                .expect("assemble member evidence");
                SubmissionMember {
                    capacity_evidence: ev,
                    operative: OperativeContext {
                        holder_id: "holder:example".into(),
                        pool_id: "pool:default".into(),
                    },
                }
            })
            .collect()
    }

    #[test]
    fn assembles_a_three_member_leaf() {
        let (closure, _) = windows();
        let (_sd_pk, sd_sk) = mldsa::keypair();
        let ks = HolderKeySet::generate(4);
        let set = assemble_submission_set(members_n(3, &sd_sk, &ks), RULES, SRF, closure)
            .expect("a well-formed three-member leaf must assemble");
        assert_eq!(set.certificates.len(), 3, "all three members carried");
        assert!(!set.submission_set_id.is_empty());
    }

    #[test]
    fn single_member_is_the_degenerate_leaf() {
        let (closure, _) = windows();
        let (_sd_pk, sd_sk) = mldsa::keypair();
        let ks = HolderKeySet::generate(1);
        let set = assemble_submission_set(members_n(1, &sd_sk, &ks), RULES, SRF, closure)
            .expect("the single-member set is the degenerate leaf, still valid");
        assert_eq!(set.certificates.len(), 1);
    }

    #[test]
    fn empty_set_is_rejected() {
        let (closure, _) = windows();
        let err = assemble_submission_set(vec![], RULES, SRF, closure)
            .expect_err("an empty leaf is meaningless");
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn over_cardinality_set_is_rejected() {
        // submission-set/1 §8.1: refuse to assemble > MAX_SUBMISSION_SET_MEMBERS.
        // The length guard fires before the per-member loop, so cloning one member
        // (MAX+1) times with distinct ids is enough to exercise it cheaply.
        use capacity_artifacts::submission_set::MAX_SUBMISSION_SET_MEMBERS;
        let (closure, _) = windows();
        let (_sd_pk, sd_sk) = mldsa::keypair();
        let ks = HolderKeySet::generate(1);
        let proto = members_n(1, &sd_sk, &ks).pop().unwrap();
        let members: Vec<SubmissionMember> = (0..=MAX_SUBMISSION_SET_MEMBERS)
            .map(|_| proto.clone())
            .collect();
        assert_eq!(members.len(), MAX_SUBMISSION_SET_MEMBERS + 1);
        let err = assemble_submission_set(members, RULES, SRF, closure)
            .expect_err("an over-cardinality set must be refused");
        assert!(
            err.contains("maximum") && err.contains("§8.1"),
            "got: {err}"
        );
    }

    #[test]
    fn mixed_authorization_in_one_leaf_is_rejected() {
        // Two members under DIFFERENT holder key sets ⇒ different
        // holder_key_set_root ⇒ they belong to distinct authorizations and must
        // not share a leaf. (Node construction hygiene; the issuance service re-verifies
        // regardless.)
        let (closure, _) = windows();
        let (_sd_pk, sd_sk) = mldsa::keypair();
        let ks_a = HolderKeySet::generate(1);
        let ks_b = HolderKeySet::generate(1);
        let mut members = members_n(1, &sd_sk, &ks_a);
        members.extend(members_n(1, &sd_sk, &ks_b));
        let err = assemble_submission_set(members, RULES, SRF, closure)
            .expect_err("members of distinct authorizations must form distinct sets");
        assert!(err.contains("mixes capacity authorizations"), "got: {err}");
    }
}
