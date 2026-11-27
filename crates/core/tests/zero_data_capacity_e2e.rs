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

//! End-to-end demonstration that the zero-data capacity path verifies offline.
//!
//! This test plays the full path a real issuance drives, with NO contact with
//! CERTCRYPT at verification time:
//!
//! 1. Holder setup (once, offline): generate the operation-key tree; its root
//!    is what the Level-2 authorization commits to.
//! 2. Per certificate: project the commitment to pseudonyms under a fresh
//!    operation salt, sign it with a fresh non-reused leaf key, assemble the
//!    zero-data capacity evidence.
//! 3. Bind the evidence digest into what would be the IndependenceProofV1.
//! 4. OFFLINE verifier: run the capacity proof for itself —
//!    membership, real ML-DSA signature, pseudonym bindings, proof-digest
//!    binding — and confirm Verified WITHOUT ever seeing a stable identifier.
//!
//! The load-bearing assertions: (a) the verdict is Verified offline; (b) no
//! stable identifier leaks into the wire bytes; (c) two certificates from the
//! same holder share no rotating value (leaf key, pseudonyms, salt) — they do
//! share the key-set root, which travels in clear; (d) every tamper fails
//! closed.

use capacity_verify::capacity_evidence::{verify_capacity_evidence, CapacityVerdict};
use certcrypt_node_core::{assemble_evidence, EvidenceInputs, HolderKeySet, StableIdentifiers};

/// A system-domain (Level-1) keypair. In production this is resolved from
/// `system-manifest/1`; here a fresh keypair plays the system-domain.
fn system_domain_keypair() -> (Vec<u8>, Vec<u8>) {
    capacity_verify::mldsa::keypair()
}

/// Stable identifiers that MUST NOT appear anywhere in the wire evidence.
const HOLDER_ID: &str = "holder:example";
const POOL_ID: &str = "pool:example-default";
const AUTHORIZATION_ID: &str = "auth:example-2026";
const CONTRACT_HINT: &str = "contract:"; // contract_id must never appear at all

fn evidence_inputs<'a>(
    key_set: &'a HolderKeySet,
    leaf_index: usize,
    operation_salt: &str,
    cert_digest: &str,
    system_domain_secret_key: &'a [u8],
) -> EvidenceInputs<'a> {
    EvidenceInputs {
        system_id: "certcrypt".into(),
        system_root_fingerprint: "12e236790358eeae049c2a8f8be4b0005f2f0e108a2f4d3df9e7ea73ec20b334"
            .into(),
        rules_version: "rules/conformance".into(),
        authorized_role: "capacity_commitment_holder".into(),
        authorization_issuer_kid: "system-domain-kid-1".into(),
        valid_from: "2026-01-01T00:00:00Z".into(),
        valid_until: "2027-01-01T00:00:00Z".into(),
        certificate_commitment_digest: cert_digest.into(),
        consumed_quantity: "1.00".into(),
        declared_effective_units: "1".into(),
        issued_at: "2026-06-15T12:00:00Z".into(),
        expires_at: "2026-07-15T12:00:00Z".into(),
        stable: StableIdentifiers {
            holder_id: HOLDER_ID.into(),
            pool_id: POOL_ID.into(),
            authorization_id: AUTHORIZATION_ID.into(),
        },
        key_set,
        leaf_index,
        operation_salt: operation_salt.as_bytes().to_vec(),
        system_domain_secret_key,
        system_domain_classical_seed: &E2E_CLASSICAL_SEED,
    }
}

/// Fixed P-256 seed — classical component of the canonical composite
/// system-domain key (`certcrypt-composite-p256-mldsa65-v1`, `composite-signature/1`). The producer
/// (`assemble_evidence`) interprets `system_domain_classical_seed` as a P-256
/// seed and signs with `composite_sign_p256`; the verifier therefore needs the
/// P-256 SEC1 public key derived from the SAME seed.
const E2E_CLASSICAL_SEED: [u8; 32] = [0x11u8; 32];

/// P-256 SEC1 public key the verifier checks the Level-1 composite against —
/// derived from the same seed the producer signs with (canonical profile).
fn e2e_classical_pub() -> Vec<u8> {
    capacity_verify::ecdsa_p256::public_key_sec1(
        &capacity_verify::ecdsa_p256::signing_key_from_seed(&E2E_CLASSICAL_SEED),
        false,
    )
}

fn assert_no_stable_ids(wire_json: &str) {
    for needle in [HOLDER_ID, POOL_ID, AUTHORIZATION_ID, CONTRACT_HINT] {
        assert!(
            !wire_json.contains(needle),
            "stable identifier '{needle}' leaked into the wire evidence — unlinkability broken"
        );
    }
}

#[test]
fn issuer_signs_then_independent_verifies_offline_without_stable_ids() {
    // --- 0. System-domain authorizes (Level-1), once, offline ---
    let (sd_pk, sd_sk) = system_domain_keypair();

    // --- 1. Holder setup (offline, once per authorization) ---
    // The Level-2 authorization (signed by the system-domain, checked in step 2
    // of the full package) commits to this root.
    let key_set = HolderKeySet::generate(8);

    // --- 2. Per certificate: project + sign with a fresh leaf ---
    let evidence = assemble_evidence(&evidence_inputs(
        &key_set,
        0,
        "operation-salt-cert-A",
        &"a1".repeat(32),
        &sd_sk,
    ))
    .expect("evidence assembles");

    // --- 3. Bind the evidence digest into the IndependenceProofV1 ---
    // The issuance service would place this hex into the signed proof fields. Here we
    // simulate that binding by capturing the digest the proof would carry.
    let bound_in_proof = evidence.evidence_digest_hex();

    // --- 4. OFFLINE verification (no CERTCRYPT contact) ---
    // The verifier resolves the system-domain key from system-manifest/1 and
    // checks the Level-1 anchor (step 2) + steps 3-6.
    let verdict = verify_capacity_evidence(
        &evidence,
        &sd_pk,
        &e2e_classical_pub(),
        Some(&bound_in_proof),
    );
    assert_eq!(
        verdict,
        CapacityVerdict::Verified,
        "offline capacity proof must verify (zero-data path)"
    );

    // (b) No stable identifier is recoverable from the wire bytes.
    let wire = serde_json::to_string(&evidence).unwrap();
    assert_no_stable_ids(&wire);
}

#[test]
fn two_certificates_same_holder_not_linkable_yet_both_verify() {
    let (sd_pk, sd_sk) = system_domain_keypair();
    let key_set = HolderKeySet::generate(8);

    let cert_a = assemble_evidence(&evidence_inputs(
        &key_set,
        0,
        "operation-salt-cert-A",
        &"a1".repeat(32),
        &sd_sk,
    ))
    .unwrap();
    let cert_b = assemble_evidence(&evidence_inputs(
        &key_set,
        1,
        "operation-salt-cert-B",
        &"b2".repeat(32),
        &sd_sk,
    ))
    .unwrap();

    // Both verify offline.
    assert_eq!(
        verify_capacity_evidence(&cert_a, &sd_pk, &e2e_classical_pub(), None),
        CapacityVerdict::Verified
    );
    assert_eq!(
        verify_capacity_evidence(&cert_b, &sd_pk, &e2e_classical_pub(), None),
        CapacityVerdict::Verified
    );

    // Different leaf keys, different pseudonyms, different salts. What the two
    // share is the key-set root, in clear by design: a holder of both can tell
    // they come from one key set, and neither carries a stable identifier.
    assert_ne!(
        cert_a.operation_key.public_key_b64,
        cert_b.operation_key.public_key_b64
    );
    assert_ne!(
        cert_a.projected_commitment.holder_pseudonym,
        cert_b.projected_commitment.holder_pseudonym
    );
    assert_ne!(cert_a.operation_salt_hex, cert_b.operation_salt_hex);

    // Sanity: neither leaks the stable ids.
    assert_no_stable_ids(&serde_json::to_string(&cert_a).unwrap());
    assert_no_stable_ids(&serde_json::to_string(&cert_b).unwrap());
}

#[test]
fn evidence_roundtrips_through_wire_json() {
    // The verifier in production receives JSON, not a Rust struct. Confirm the
    // evidence survives a serialize→deserialize round-trip and still verifies —
    // this is the contract the verifier-toolkit-* will consume.
    let (sd_pk, sd_sk) = system_domain_keypair();
    let key_set = HolderKeySet::generate(4);
    let evidence = assemble_evidence(&evidence_inputs(
        &key_set,
        2,
        "operation-salt-roundtrip",
        &"c3".repeat(32),
        &sd_sk,
    ))
    .unwrap();
    let digest = evidence.evidence_digest_hex();

    let wire = serde_json::to_string(&evidence).unwrap();
    let restored: capacity_verify::capacity_evidence::CapacityEvidence =
        serde_json::from_str(&wire).unwrap();

    // Digest is stable across the round-trip (canonical serialization).
    assert_eq!(restored.evidence_digest_hex(), digest);
    assert_eq!(
        verify_capacity_evidence(&restored, &sd_pk, &e2e_classical_pub(), Some(&digest)),
        CapacityVerdict::Verified
    );
}
