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

//! A fully signed zero-data submission set, for tests that need a real one.
//!
//! The node never mints an emission key: an issuer does. So a test that exercises
//! the submit path has to stand in for the issuer AND for the system domain, and
//! that is all this module is — fixture material, built from the protocol core
//! with no shortcuts, so the wire payload a test sends is the genuine shape
//! rather than a hand-written approximation that would pass a handler and fail a
//! verifier.
//!
//! Everything here is synthetic and fixed: the seeds are constants, the
//! identifiers are placeholders. Nothing in it describes a deployment.

#![allow(dead_code)] // Not every integration test needs every helper.

use capacity_artifacts::submission_set::{
    OperativeContext, SubmissionSetCertificateV1, SubmissionSetV1, SUBMISSION_SET_VERSION,
    SYSTEM_ID_ACTIVE,
};
use capacity_verify::capacity_evidence::{assemble_evidence, EvidenceInputs, StableIdentifiers};
use capacity_verify::holder_keyset::HolderKeySet;
use capacity_verify::manifest::{ResolvedManifestEntry, StaticManifestResolver};
use capacity_verify::mldsa;
use chrono::{DateTime, Duration, TimeZone, Utc};

/// The rules domain this fixture material is built under: the stub domain, which
/// anchors on nothing. Test material must describe a synthetic deployment,
/// never a live one.
pub const ACTIVE_RULES: &str = "rules/conformance";
pub const DEV_FINGERPRINT: &str =
    "abababababababababababababababababababababababababababababababab";
pub const DEV_L1_KID: &str = "system-domain-kid-1";
/// Fixed 32-byte seed for the classical (ECDSA P-256) component of the composite
/// system-domain key (`composite-signature/1`, canonical profile).
pub const DEV_L1_CLASSICAL_SEED: [u8; 32] = [0x5au8; 32];
pub const DEV_AUTHORIZED_ROLE: &str = "capacity_commitment_holder";
pub const DEV_HOLDER_ID: &str = "holder:6ba7b811-9dad-41d4-a716-446655440000";
pub const DEV_POOL_ID: &str = "default";
pub const DEV_AUTHORIZATION_ID: &str = "auth:6ba7b812-9dad-41d4-a716-446655440000";

/// One fully signed zero-data test submission set plus the resolver that
/// recognizes its system-domain key. Tests seat the resolver on `AppState` so
/// the handler can verify the evidence end-to-end.
///
/// `holder_key_set` + `system_domain_sk` are retained so callers can re-assemble
/// tampered or additional evidence in negative tests (the node never mints the
/// emission key, but tests stand in for the issuer + the system-domain).
pub struct DevSubmissionSetFixture {
    pub submission_set: SubmissionSetV1,
    pub resolver: StaticManifestResolver,
    pub holder_key_set: HolderKeySet,
    pub system_domain_sk: Vec<u8>,
}

impl DevSubmissionSetFixture {
    /// Mint a second submission set re-using this fixture's holder key set +
    /// system-domain key. A different `closure_time` and a fresh per-operation
    /// salt + a distinct leaf produce a distinct `submission_set_id` (and a
    /// distinct evidence digest) so the issuance service's deduplication does
    /// not fire. The
    /// original resolver still resolves the chain because the L1 key is
    /// unchanged.
    pub fn mint_additional_submission_set(
        &self,
        closure_time: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> SubmissionSetV1 {
        // issued_at derived from the domain TTL, not from an arbitrary offset: the
        // verifier requires expires_at == issued_at + ttl(rules_version), and the
        // issuance service and the node enforce the same equality at submit. A
        // fixture with any other window would produce material that never verifies.
        let issued_at = expires_at
            - Duration::seconds(i64::from(
                capacity_artifacts::settlement::commitment_ttl_seconds_for(ACTIVE_RULES)
                    .expect("ACTIVE_RULES must declare a commitment TTL"),
            ));
        // A distinct leaf (1) + fresh salt keeps it unlinkable from the original
        // member (leaf 0). The key set must have been generated with size >= 2.
        let cert = build_zero_data_cert(
            &self.holder_key_set,
            1,
            b"op-salt-additional".to_vec(),
            &self.system_domain_sk,
            issued_at,
            expires_at,
        );
        finish_set(vec![cert], closure_time)
    }
}

/// Build a single-certificate zero-data submission set whose evidence verifies.
/// `expires_at` is the commitment expiry; pass a value comfortably after
/// `Utc::now()` to keep the dual temporal check happy when the handler stamps
/// `submit_received_at`.
pub fn make_dev_submission_set(
    closure_time: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> DevSubmissionSetFixture {
    make_dev_submission_set_n(closure_time, expires_at, 1)
}

/// Build an N-certificate zero-data submission set whose evidence verifies: N
/// autonomous members under ONE holder key set + ONE system-domain key (so they
/// share the same authorization anchor and form one settlement leaf), each
/// signed by a DISTINCT leaf (non-reuse) under a fresh per-operation salt.
pub fn make_dev_submission_set_n(
    closure_time: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    n: usize,
) -> DevSubmissionSetFixture {
    assert!(n >= 1, "submission set needs at least one member");
    let (l1_pk, l1_sk) = mldsa::keypair();

    let mut resolver = StaticManifestResolver::new();
    resolver.insert(
        DEV_FINGERPRINT,
        ResolvedManifestEntry {
            kid: DEV_L1_KID.into(),
            algorithm: capacity_artifacts::composite_sig::PROFILE_P256_MLDSA65.into(),
            public_key: l1_pk,
            classical_public_key: capacity_verify::ecdsa_p256::public_key_sec1(
                &capacity_verify::ecdsa_p256::signing_key_from_seed(&DEV_L1_CLASSICAL_SEED),
                false,
            ),
            valid_from: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            valid_until: Some(Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap()),
        },
    );

    // One holder key set with at least 2 leaves so `mint_additional_submission_set`
    // (which uses leaf 1) always has a spare non-reused leaf.
    let key_set = HolderKeySet::generate(n.max(2));
    // Same reasoning as in mint_additional_submission_set: the window must be the
    // domain's, or the fixture signs something no verifier accepts.
    let issued_at = expires_at
        - Duration::seconds(i64::from(
            capacity_artifacts::settlement::commitment_ttl_seconds_for(ACTIVE_RULES)
                .expect("ACTIVE_RULES must declare a commitment TTL"),
        ));

    let certs: Vec<SubmissionSetCertificateV1> = (0..n)
        .map(|i| {
            build_zero_data_cert(
                &key_set,
                i,
                format!("op-salt-{i}").into_bytes(),
                &l1_sk,
                issued_at,
                expires_at,
            )
        })
        .collect();

    let submission_set = finish_set(certs, closure_time);

    DevSubmissionSetFixture {
        submission_set,
        resolver,
        holder_key_set: key_set,
        system_domain_sk: l1_sk,
    }
}

/// Assemble one zero-data certificate: produce signed `CapacityEvidence` for the
/// given leaf + salt and wrap it with its operative context.
fn build_zero_data_cert(
    key_set: &HolderKeySet,
    leaf_index: usize,
    operation_salt: Vec<u8>,
    system_domain_sk: &[u8],
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> SubmissionSetCertificateV1 {
    let evidence = assemble_evidence(&EvidenceInputs {
        system_id: SYSTEM_ID_ACTIVE.into(),
        system_root_fingerprint: DEV_FINGERPRINT.into(),
        rules_version: ACTIVE_RULES.into(),
        authorized_role: DEV_AUTHORIZED_ROLE.into(),
        authorization_issuer_kid: DEV_L1_KID.into(),
        valid_from: "2026-01-01T00:00:00Z".into(),
        valid_until: "2099-01-01T00:00:00Z".into(),
        certificate_commitment_digest:
            "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef".into(),
        consumed_quantity: "1".into(),
        declared_effective_units: "1".into(),
        issued_at: rfc3339_secs(issued_at),
        expires_at: rfc3339_secs(expires_at),
        stable: StableIdentifiers {
            holder_id: DEV_HOLDER_ID.into(),
            pool_id: DEV_POOL_ID.into(),
            authorization_id: DEV_AUTHORIZATION_ID.into(),
        },
        key_set,
        leaf_index,
        operation_salt,
        system_domain_secret_key: system_domain_sk,
        system_domain_classical_seed: &DEV_L1_CLASSICAL_SEED,
    })
    .expect("assemble dev capacity evidence");

    SubmissionSetCertificateV1 {
        capacity_evidence: evidence,
        operative: OperativeContext {
            holder_id: DEV_HOLDER_ID.into(),
            pool_id: DEV_POOL_ID.into(),
        },
    }
}

/// Wrap assembled certificates into a `SubmissionSetV1` with a recomputed id.
fn finish_set(
    certificates: Vec<SubmissionSetCertificateV1>,
    closure_time: DateTime<Utc>,
) -> SubmissionSetV1 {
    let submission_set_id = SubmissionSetV1::compute_submission_set_id(
        SUBMISSION_SET_VERSION,
        SYSTEM_ID_ACTIVE,
        ACTIVE_RULES,
        DEV_FINGERPRINT,
        &closure_time,
        &certificates,
    )
    .expect("compute submission_set_id");

    SubmissionSetV1 {
        schema: SUBMISSION_SET_VERSION.into(),
        system_id: SYSTEM_ID_ACTIVE.into(),
        rules_version: ACTIVE_RULES.into(),
        system_root_fingerprint: DEV_FINGERPRINT.into(),
        submission_set_id,
        closure_time,
        certificates,
    }
}

/// RFC 3339, second precision, 'Z' — the form the projected commitment carries
/// and the verifier reproduces.
fn rfc3339_secs(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
