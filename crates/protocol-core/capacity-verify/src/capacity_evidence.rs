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

//! Zero-data capacity evidence — the OFFLINE verifier.
//!
//! The wire types (`CapacityEvidence`, `ProjectedCommitment`,
//! `ProjectedAuthorization`, `OperationKeyDisclosure`) are closed-schema
//! artifacts and live in [`capacity_artifacts::capacity_evidence`]. This module
//! owns the verifier — it needs ML-DSA, so it sits in `capacity-verify`.
//! Keeping the verifier here means the online submit path and the offline
//! verifier run the SAME
//! verification code: one Rust verifier, no drift. Parity with the TypeScript
//! verifier is held by the conformance goldens.
//!
//! The PRODUCER (`assemble_evidence`, which holds the holder operation-key
//! secrets and the system-domain Level-1 secret) lives in
//! this module.

use crate::mldsa;
use base64::Engine as _;
use sha3::{Digest, Sha3_256};

// Re-export the wire types (defined in `capacity-artifacts`) through this module,
// so downstream code can import them as
// `capacity_verify::capacity_evidence::{CapacityEvidence, ProjectedCommitment, ...}`.
pub use capacity_artifacts::capacity_evidence::{
    operation_key_leaf_hash, CapacityEvidence, OperationKeyDisclosure, ProjectedAuthorization,
    ProjectedCommitment, ZERO_DATA_PROFILE,
};

/// Outcome of offline capacity-evidence verification. Fail-closed:
/// any redaction/inconsistency yields `Unverifiable`, never a partial pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityVerdict {
    /// The holder consumed system-domain-authorized capacity, provable offline
    /// without stable identifiers.
    Verified,
    /// Evidence is absent, redacted, inconsistent, or its signature/membership
    /// does not check out. Indistinguishable from absent evidence by design.
    Unverifiable(String),
}

fn decode_lower_hex_bytes(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex::decode(value).ok()
}

fn parse_commitment_instant(value: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    let instant = chrono::DateTime::parse_from_rfc3339(value).ok()?;
    (instant.timestamp_subsec_nanos() == 0
        && instant.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) == value)
        .then_some(instant)
}

/// Verify zero-data capacity evidence offline.
///
/// The system-domain Level-1 verification keys (the verifier resolves both from
/// `system-manifest/1` via the evidence's `authorization_issuer_kid`) are the
/// two COMPOSITE components (`composite-signature/1`): the holder_key_set_root anchor is signed as a
/// PQ/T hybrid composite. `expected_evidence_digest` is the digest bound in the
/// `IndependenceProofV1` (`independence.proof/1` §7); pass `None` to skip that binding check in isolation.
pub fn verify_capacity_evidence(
    evidence: &CapacityEvidence,
    system_domain_mldsa_public_key: &[u8],
    // The system-domain CLASSICAL public key of the composite: P-256 SEC1 for the
    // canonical profile, or Ed25519 raw-32 for the additional profile. The
    // composite verifier picks the algorithm from the signature's component.
    system_domain_classical_public_key: &[u8],
    expected_evidence_digest: Option<&str>,
) -> CapacityVerdict {
    // Profile + salt present (fail-closed on incomplete redaction).
    if evidence.profile != ZERO_DATA_PROFILE {
        return CapacityVerdict::Unverifiable(format!("unexpected profile: {}", evidence.profile));
    }
    let salt = match decode_lower_hex_bytes(&evidence.operation_salt_hex) {
        Some(s) => s,
        _ => return CapacityVerdict::Unverifiable("operation_salt missing or invalid".into()),
    };

    let auth = &evidence.projected_authorization;
    let com = &evidence.projected_commitment;

    // Step 1 (the trust anchor): verify the system-domain Level-1
    // signature over the authorization binding, and that the binding commits to
    // the SAME holder_key_set_root the membership check (step 2) will use. This
    // is what stops a holder from fabricating their own root.
    let binding = &auth.level1_binding;
    if binding.holder_key_set_root != auth.holder_key_set_root {
        return CapacityVerdict::Unverifiable(
            "level1_binding root does not match projected holder_key_set_root".into(),
        );
    }
    if binding.system_id != auth.system_id
        || binding.rules_version != auth.rules_version
        || binding.system_root_fingerprint != auth.system_root_fingerprint
        || binding.authorized_role != auth.authorized_role
        || binding.authorization_issuer_kid != auth.authorization_issuer_kid
        || binding.valid_from != auth.valid_from
        || binding.valid_until != auth.valid_until
    {
        return CapacityVerdict::Unverifiable(
            "level1_binding fields do not match projected authorization".into(),
        );
    }
    // The authorization grants exactly the commitment-holder role
    // (`capacity.holder-authorization/1` §7 step 2); any other role is refused.
    if binding.authorized_role != capacity_artifacts::capacity_holder_authorization::AUTHORIZED_ROLE
    {
        return CapacityVerdict::Unverifiable(format!(
            "authorized_role is {:?}, expected {:?}",
            binding.authorized_role,
            capacity_artifacts::capacity_holder_authorization::AUTHORIZED_ROLE
        ));
    }
    // The commitment is signed inside the authorization's window
    // (`capacity.holder-authorization/1` §5.1, verifier obligation §7 step 4):
    // `issued_at` in [valid_from, valid_until], inclusive. Unparseable bounds
    // refuse too. Same check, same order, as the JS toolkit.
    let parse_auth = |t: &str| chrono::DateTime::parse_from_rfc3339(t).ok();
    match (
        parse_commitment_instant(&com.issued_at),
        parse_commitment_instant(&com.expires_at),
        parse_auth(&binding.valid_from),
        parse_auth(&binding.valid_until),
    ) {
        (Some(issued), Some(_expires), Some(from), Some(until)) => {
            if issued < from || issued > until {
                return CapacityVerdict::Unverifiable(format!(
                    "commitment issued_at={} falls outside the authorization window [{}, {}]",
                    com.issued_at, binding.valid_from, binding.valid_until
                ));
            }
        }
        _ => {
            return CapacityVerdict::Unverifiable(format!(
                "non-canonical commitment instant or unparseable authorization window (valid_from={}, valid_until={}, issued_at={}, expires_at={})",
                binding.valid_from, binding.valid_until, com.issued_at, com.expires_at
            ))
        }
    }
    let binding_bytes = match binding.signing_bytes() {
        Ok(b) => b,
        Err(_) => return CapacityVerdict::Unverifiable("level-1 binding bytes".into()),
    };
    // Composite L1 anchor (`composite-signature/1`): both components sign M'(SHA3(binding_bytes)); AND.
    let binding_digest_hex = hex::encode(Sha3_256::digest(&binding_bytes));
    if crate::composite::verify_composite(
        crate::composite::REQUIRED_PROFILE,
        &binding_digest_hex,
        &auth.level1_signature,
        crate::composite::CompositePublicKeys {
            classical_pub: system_domain_classical_public_key,
            mldsa_pub: system_domain_mldsa_public_key,
        },
    )
    .is_err()
    {
        return CapacityVerdict::Unverifiable(
            "level-1 composite signature does not verify against system-domain key — \
             holder_key_set_root is not system-domain-authorized"
                .into(),
        );
    }

    // Step 2: leaf key membership in the authorized operation-key root.
    if !evidence
        .operation_key
        .verify_membership(&auth.holder_key_set_root)
    {
        return CapacityVerdict::Unverifiable(
            "operation key not a member of holder_key_set_root".into(),
        );
    }

    // Step 3: real ML-DSA-65 verification of the projected commitment against
    // the disclosed leaf key (NOT an opaque commitment).
    let leaf_pk = match evidence.operation_key.public_key() {
        Some(pk) => pk,
        None => return CapacityVerdict::Unverifiable("leaf public key undecodable".into()),
    };
    let sig = match base64::engine::general_purpose::STANDARD
        .decode(evidence.commitment_signature_b64.as_bytes())
    {
        Ok(s) => s,
        Err(_) => return CapacityVerdict::Unverifiable("commitment signature undecodable".into()),
    };
    if mldsa::verify_detached(&leaf_pk, &sig, &com.signing_bytes()).is_err() {
        return CapacityVerdict::Unverifiable(
            "commitment signature does not verify against operation leaf key".into(),
        );
    }

    // Step 4: internal pseudonym bindings — commitment and authorization must
    // agree on the holder and authorization pseudonyms (recomputed under the
    // same salt). This is anti-splicing on pseudonyms, not on cleartext ids.
    if com.holder_pseudonym != auth.holder_pseudonym {
        return CapacityVerdict::Unverifiable(
            "holder pseudonym mismatch between commitment and authorization".into(),
        );
    }
    if com.authorization_pseudonym != auth.authorization_pseudonym {
        return CapacityVerdict::Unverifiable(
            "authorization pseudonym mismatch between commitment and authorization".into(),
        );
    }

    // Coherence: commitment and authorization must share the system context.
    if com.system_id != auth.system_id
        || com.rules_version != auth.rules_version
        || com.system_root_fingerprint != auth.system_root_fingerprint
    {
        return CapacityVerdict::Unverifiable("system context mismatch".into());
    }

    // Step 5: bind evidence digest to the IndependenceProofV1 (anti-splicing).
    if let Some(expected) = expected_evidence_digest {
        if evidence.evidence_digest_hex() != expected {
            return CapacityVerdict::Unverifiable(
                "capacity evidence digest does not match the digest bound in the proof".into(),
            );
        }
    }

    // (We intentionally do not re-derive pseudonyms from cleartext ids here:
    // the verifier never receives the cleartext ids — that is the whole point.
    // `salt` presence is enforced above so the binding is reproducible by any
    // party that DOES hold an id, e.g. the issuer auditing its own evidence.)
    let _ = salt;

    CapacityVerdict::Verified
}

// ===========================================================================
// PRODUCER
// ===========================================================================
//
// The producer holds the only secrets in this module: the holder operation-key
// secret keys (via [`HolderKeySet`]) and the system-domain Level-1 secret. It
// lives in the same shared crate as the verifier so the online submit path and
// the node assemble + verify with one implementation — no drift. The wire types
// remain closed-schema artifacts in `capacity-artifacts`.

use crate::holder_keyset::HolderKeySet;
use capacity_artifacts::pseudonym::{self, Domain};
use capacity_artifacts::Level1AuthorizationBinding;

/// Stable identifiers the holder/node holds privately and projects. These never
/// appear in the evidence; only their pseudonyms do.
#[derive(Debug, Clone)]
pub struct StableIdentifiers {
    pub holder_id: String,
    pub pool_id: String,
    pub authorization_id: String,
}

/// Inputs to assemble capacity evidence for one commitment.
pub struct EvidenceInputs<'a> {
    pub system_id: String,
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
    /// Canonical decimal/integer string. Bound into the signed projected
    /// commitment, the value the `cost_commitment` preimage commits to.
    pub declared_effective_units: String,
    pub issued_at: String,
    pub expires_at: String,
    pub stable: StableIdentifiers,
    /// The holder's authorized operation-key tree (its root is what the
    /// authorization commits to).
    pub key_set: &'a HolderKeySet,
    /// Which leaf signs this commitment. MUST NOT be reused across commitments.
    pub leaf_index: usize,
    /// Fresh public per-operation salt. MUST be unique per operation.
    pub operation_salt: Vec<u8>,
    /// System-domain (Level-1) secret key that authorizes the holder's
    /// operation-key tree root. Signed ONCE, offline, over the
    /// [`Level1AuthorizationBinding`] — not per operation. Outside tests the
    /// system domain produces this signature when it authorizes the holder;
    /// here it is an input so the evidence carries the verifiable anchor.
    pub system_domain_secret_key: &'a [u8],
    /// 32-byte seed of the classical (ECDSA P-256) component of the composite
    /// Level-1 key (`composite-signature/1`).
    pub system_domain_classical_seed: &'a [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("leaf_index {0} out of range for key set")]
    LeafOutOfRange(usize),
    #[error("signing failed: {0}")]
    Signing(String),
}

/// Assemble zero-data capacity evidence: project the commitment + authorization
/// to pseudonyms, sign the projected commitment with the per-operation leaf
/// key, and disclose the leaf + its membership proof.
pub fn assemble_evidence(inputs: &EvidenceInputs<'_>) -> Result<CapacityEvidence, EvidenceError> {
    let salt = &inputs.operation_salt;
    let holder_pseudonym = pseudonym::derive(salt, Domain::Holder, &inputs.stable.holder_id);
    let pool_pseudonym = pseudonym::derive(salt, Domain::Pool, &inputs.stable.pool_id);
    let authorization_pseudonym =
        pseudonym::derive(salt, Domain::Authorization, &inputs.stable.authorization_id);

    let projected_commitment = ProjectedCommitment {
        commitment_version: "capacity.commitment/1".to_string(),
        system_id: inputs.system_id.clone(),
        system_root_fingerprint: inputs.system_root_fingerprint.clone(),
        rules_version: inputs.rules_version.clone(),
        authorization_pseudonym: authorization_pseudonym.clone(),
        holder_pseudonym: holder_pseudonym.clone(),
        pool_pseudonym: pool_pseudonym.clone(),
        certificate_commitment_digest: inputs.certificate_commitment_digest.clone(),
        consumed_quantity: inputs.consumed_quantity.clone(),
        declared_effective_units: inputs.declared_effective_units.clone(),
        issued_at: inputs.issued_at.clone(),
        expires_at: inputs.expires_at.clone(),
    };

    let key = inputs
        .key_set
        .key(inputs.leaf_index)
        .ok_or(EvidenceError::LeafOutOfRange(inputs.leaf_index))?;
    let signature = mldsa::sign_detached(&key.secret_key, &projected_commitment.signing_bytes())
        .map_err(|e| EvidenceError::Signing(format!("{e:?}")))?;

    let disclosure = inputs
        .key_set
        .disclosure(inputs.leaf_index)
        .ok_or(EvidenceError::LeafOutOfRange(inputs.leaf_index))?;

    // Level-1 binding: the system-domain signs the holder_key_set_root (plus
    // non-correlating context). This is the trust anchor verified in step 1.
    let level1_binding = Level1AuthorizationBinding {
        system_id: inputs.system_id.clone(),
        rules_version: inputs.rules_version.clone(),
        system_root_fingerprint: inputs.system_root_fingerprint.clone(),
        authorized_role: inputs.authorized_role.clone(),
        authorization_issuer_kid: inputs.authorization_issuer_kid.clone(),
        valid_from: inputs.valid_from.clone(),
        valid_until: inputs.valid_until.clone(),
        holder_key_set_root: inputs.key_set.root().to_string(),
    };
    let level1_binding_bytes = level1_binding
        .signing_bytes()
        .map_err(|e| EvidenceError::Signing(format!("level-1 binding bytes: {e}")))?;
    // Canonical composite L1 signature (`composite-signature/1`): P-256 (classical) + ML-DSA over
    // M'(SHA3(binding_bytes)). The seed is reused as the P-256 scalar seed.
    let level1_binding_digest_hex = hex::encode(Sha3_256::digest(&level1_binding_bytes));
    let sd_p256 = crate::ecdsa_p256::signing_key_from_seed(inputs.system_domain_classical_seed);
    let level1_composite = crate::composite::composite_sign_p256(
        &level1_binding_digest_hex,
        &sd_p256,
        inputs.system_domain_secret_key,
    )
    .map_err(|e| EvidenceError::Signing(format!("level-1 composite: {e}")))?;

    let projected_authorization = ProjectedAuthorization {
        system_id: inputs.system_id.clone(),
        rules_version: inputs.rules_version.clone(),
        system_root_fingerprint: inputs.system_root_fingerprint.clone(),
        authorized_role: inputs.authorized_role.clone(),
        authorization_issuer_kid: inputs.authorization_issuer_kid.clone(),
        valid_from: inputs.valid_from.clone(),
        valid_until: inputs.valid_until.clone(),
        holder_key_set_root: inputs.key_set.root().to_string(),
        level1_binding,
        level1_signature: level1_composite,
        authorization_pseudonym,
        holder_pseudonym,
    };
    Ok(CapacityEvidence {
        profile: ZERO_DATA_PROFILE.to_string(),
        operation_salt_hex: hex::encode(salt),
        projected_authorization,
        projected_commitment,
        operation_key: disclosure,
        commitment_signature_b64: base64::engine::general_purpose::STANDARD.encode(&signature),
    })
}

#[cfg(test)]
mod producer_tests {
    use super::*;

    /// A fresh system-domain (Level-1) keypair for tests. Outside tests this is
    /// the system-domain key resolved from `system-manifest/1`.
    fn system_domain() -> (Vec<u8>, Vec<u8>) {
        mldsa::keypair()
    }

    /// P-256 classical public key (SEC1) for the fixed test seed `inputs_with`
    /// signs the canonical composite with.
    fn ed_pk() -> Vec<u8> {
        crate::ecdsa_p256::public_key_sec1(
            &crate::ecdsa_p256::signing_key_from_seed(&[0x33u8; 32]),
            false,
        )
    }

    fn inputs_with<'a>(
        key_set: &'a HolderKeySet,
        leaf: usize,
        salt: &str,
        system_domain_secret_key: &'a [u8],
    ) -> EvidenceInputs<'a> {
        EvidenceInputs {
            system_id: "certcrypt".into(),
            system_root_fingerprint: "ab".repeat(32),
            rules_version: "rules/conformance".into(),
            authorized_role: "capacity_commitment_holder".into(),
            authorization_issuer_kid: "system-domain-kid-1".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
            certificate_commitment_digest: "ef".repeat(32),
            consumed_quantity: "5.00".into(),
            declared_effective_units: "1".into(),
            issued_at: "2026-06-15T12:00:00Z".into(),
            expires_at: "2026-07-15T12:00:00Z".into(),
            stable: StableIdentifiers {
                holder_id: "holder:example".into(),
                pool_id: "pool:default".into(),
                authorization_id: "auth:abc123".into(),
            },
            key_set,
            leaf_index: leaf,
            operation_salt: salt.as_bytes().to_vec(),
            system_domain_secret_key,
            system_domain_classical_seed: &[0x33u8; 32],
        }
    }

    #[test]
    fn assembled_evidence_verifies_offline() {
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(4);
        let ev = assemble_evidence(&inputs_with(&ks, 0, "op-salt-1", &sd_sk)).unwrap();
        let digest = ev.evidence_digest_hex();
        assert_eq!(
            verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), Some(&digest)),
            CapacityVerdict::Verified
        );
        // No stable identifiers appear anywhere in the serialized evidence.
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("holder:example"));
        assert!(!json.contains("pool:default"));
        assert!(!json.contains("auth:abc123"));
    }

    #[test]
    fn two_operations_same_holder_rotate_pseudonyms_but_share_the_root() {
        // Pseudonyms + operation keys ROTATE per operation (zero-PII: no stable
        // personal identifier in clear), but the holder_key_set_root is SHARED and
        // travels in clear — the intentional linkability boundary: an observer
        // MAY correlate same-key-set operations.
        // The guarantee is zero-PII and protocol-surface unlinkability, not
        // unobservability of artifacts held by a third party.
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(4);
        let e1 = assemble_evidence(&inputs_with(&ks, 0, "op-salt-1", &sd_sk)).unwrap();
        let e2 = assemble_evidence(&inputs_with(&ks, 1, "op-salt-2", &sd_sk)).unwrap();
        // Rotating, per-operation: pseudonyms + leaf operation key differ.
        assert_ne!(
            e1.projected_commitment.holder_pseudonym,
            e2.projected_commitment.holder_pseudonym
        );
        assert_ne!(
            e1.operation_key.public_key_b64,
            e2.operation_key.public_key_b64
        );
        // Stable, in clear: the key-set root is the SAME (the correlator, by design).
        assert_eq!(
            e1.projected_authorization.holder_key_set_root,
            e2.projected_authorization.holder_key_set_root,
            "same key-set ⇒ same root in clear (intentional correlation boundary)"
        );
        assert_eq!(
            verify_capacity_evidence(&e1, &sd_pk, &ed_pk(), None),
            CapacityVerdict::Verified
        );
        assert_eq!(
            verify_capacity_evidence(&e2, &sd_pk, &ed_pk(), None),
            CapacityVerdict::Verified
        );
    }

    #[test]
    fn a_commitment_outside_the_authorization_window_fails_closed() {
        // holder-authorization/1 §7 step 4: issued_at in [valid_from, valid_until].
        // Assembled honestly (every signature valid) with the commitment issued
        // before the authorization starts, then after it ends.
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(4);
        for issued_at in ["2025-12-31T23:59:59Z", "2027-01-01T00:00:01Z"] {
            let mut inputs = inputs_with(&ks, 0, "op-salt-window", &sd_sk);
            inputs.issued_at = issued_at.into();
            let ev = assemble_evidence(&inputs).unwrap();
            match verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), None) {
                CapacityVerdict::Unverifiable(why) => {
                    assert!(
                        why.contains("outside the authorization window"),
                        "{issued_at}: {why}"
                    )
                }
                other => panic!("{issued_at}: expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn non_canonical_capacity_scalars_fail_closed() {
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(4);

        for salt in ["", "0", "zz", "AA"] {
            let mut ev = assemble_evidence(&inputs_with(&ks, 0, "op-salt-shape", &sd_sk)).unwrap();
            ev.operation_salt_hex = salt.into();
            assert!(matches!(
                verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), None),
                CapacityVerdict::Unverifiable(_)
            ));
        }

        for instant in [
            "2026-02-30T00:00:00Z",
            "2026-01-01",
            "2026-01-01T00:00:00.000Z",
            "2026-01-01T01:00:00+01:00",
        ] {
            let mut ev = assemble_evidence(&inputs_with(&ks, 0, "op-salt-shape", &sd_sk)).unwrap();
            ev.projected_commitment.issued_at = instant.into();
            assert!(matches!(
                verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), None),
                CapacityVerdict::Unverifiable(_)
            ));
        }
    }

    #[test]
    fn canonical_commitment_instant_is_accepted() {
        assert!(parse_commitment_instant("2026-06-15T12:00:00Z").is_some());
    }

    #[test]
    fn an_authorization_for_another_role_fails_closed() {
        // holder-authorization/1 §7 step 2: the role is exactly
        // `capacity_commitment_holder`. Assembled honestly (every signature
        // valid, binding and projection agree) under another role.
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(4);
        let mut inputs = inputs_with(&ks, 0, "op-salt-role", &sd_sk);
        inputs.authorized_role = "capacity_observer".into();
        let ev = assemble_evidence(&inputs).unwrap();
        match verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), None) {
            CapacityVerdict::Unverifiable(why) => assert!(why.contains("authorized_role"), "{why}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn tampered_signature_fails_closed() {
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(2);
        let mut ev = assemble_evidence(&inputs_with(&ks, 0, "op-salt-1", &sd_sk)).unwrap();
        ev.commitment_signature_b64 = "AAAA".into();
        assert!(matches!(
            verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), None),
            CapacityVerdict::Unverifiable(_)
        ));
    }

    #[test]
    fn foreign_leaf_fails_membership() {
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(2);
        let other = HolderKeySet::generate(2);
        let mut ev = assemble_evidence(&inputs_with(&ks, 0, "op-salt-1", &sd_sk)).unwrap();
        // Swap the authorized root for a foreign one: it no longer matches the
        // signed binding, so step 1 (binding/root match) fails closed.
        ev.projected_authorization.holder_key_set_root = other.root().to_string();
        assert!(matches!(
            verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), None),
            CapacityVerdict::Unverifiable(_)
        ));
    }

    #[test]
    fn wrong_proof_digest_fails_closed() {
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(2);
        let ev = assemble_evidence(&inputs_with(&ks, 0, "op-salt-1", &sd_sk)).unwrap();
        assert!(matches!(
            verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), Some(&"00".repeat(32))),
            CapacityVerdict::Unverifiable(_)
        ));
    }

    #[test]
    fn spliced_authorization_pseudonym_fails() {
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(2);
        let mut ev = assemble_evidence(&inputs_with(&ks, 0, "op-salt-1", &sd_sk)).unwrap();
        ev.projected_authorization.holder_pseudonym = "ff".repeat(32);
        assert!(matches!(
            verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), None),
            CapacityVerdict::Unverifiable(_)
        ));
    }

    #[test]
    fn attacker_fabricated_root_fails_step_1() {
        // THE test that proves the hole is closed: an attacker generates their
        // OWN key set, signs the binding with their OWN key, and signs the
        // commitment with their own leaf. Steps 2-5 would all pass (internally
        // consistent) — but step 1 rejects it because the binding signature
        // does not verify against the real system-domain key.
        let (real_sd_pk, _real_sd_sk) = system_domain();
        let (_attacker_pk, attacker_sk) = system_domain(); // attacker's own L1 key
        let ks = HolderKeySet::generate(4);
        // Attacker assembles a fully self-consistent evidence signed with their
        // own system-domain key.
        let ev = assemble_evidence(&inputs_with(&ks, 0, "op-salt-1", &attacker_sk)).unwrap();
        // Verified against the REAL system-domain key → the ML-DSA component of
        // the composite L1 anchor does not verify, so it fails at the anchor step.
        let verdict = verify_capacity_evidence(&ev, &real_sd_pk, &ed_pk(), None);
        assert!(
            matches!(verdict, CapacityVerdict::Unverifiable(ref m) if m.contains("level-1")),
            "fabricated root must be rejected at step 1, got {verdict:?}"
        );
    }

    #[test]
    fn tampered_binding_field_fails_closed() {
        // Changing a binding field without re-signing (which the attacker can't
        // do without the system-domain key) must fail.
        let (sd_pk, sd_sk) = system_domain();
        let ks = HolderKeySet::generate(2);
        let mut ev = assemble_evidence(&inputs_with(&ks, 0, "op-salt-1", &sd_sk)).unwrap();
        ev.projected_authorization.level1_binding.valid_until = "2099-01-01T00:00:00Z".into();
        assert!(matches!(
            verify_capacity_evidence(&ev, &sd_pk, &ed_pk(), None),
            CapacityVerdict::Unverifiable(_)
        ));
    }
}
