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

//! `system-foundation/1` verification, and the manifest resolver built on it.
//!
//! A party that verifies issuer material but does not hold the system-domain
//! keys has to learn the Level-1 public key from somewhere it can check. The
//! canonical source is the foundation statement emitted by the key ceremony: it
//! embeds the bootstrap `system-manifest/1` version (whose digest IS the
//! `system_root_fingerprint`) and carries the Level-1 capacity key at statement
//! level, covered by a k-of-n quorum of the bootstrap members' composite
//! signatures (`system-foundation/1` §6, §9).
//!
//! [`verify_system_foundation`] runs the offline validation of
//! `system-foundation/1` §11 and, when successor-binding observations are
//! supplied with the statement, the quorum and equivocation rules of
//! `system-manifest/1` §9, §12.3 and §12.5. Nothing is half-trusted: any
//! failed check rejects the whole statement.
//!
//! [`FoundationManifestResolver`] additionally requires the recomputed bootstrap
//! fingerprint to equal the fingerprint the caller pinned, and only then
//! exposes the Level-1 capacity key.
//!
//! The check ids in the error messages are the ones the reference verifier
//! reports for the same failure, so a rejection here can be compared with the
//! conformance vectors directly.

use crate::composite::{verify_composite, CompositePublicKeys};
use crate::manifest::{derive_kid, ManifestError, ManifestResolver, ResolvedManifestEntry};
use crate::{ecdsa_p256, VerifyResult};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use capacity_artifacts::composite_sig::{CompositeSignatureWire, PROFILE_P256_MLDSA65};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;

/// `foundation_profile_id` of this profile (`system-foundation/1` §5).
pub const FOUNDATION_PROFILE: &str = "system-foundation/1";
/// `manifest_profile_id` of the embedded manifest (`system-manifest/1` §5).
pub const MANIFEST_PROFILE: &str = "system-manifest/1";
/// The only root-fingerprint derivation under `/1` (`system-foundation/1` §8).
pub const ROOT_FINGERPRINT_DERIVATION: &str = "sha3-256-system-manifest-jcs-v1";
/// `binding_profile` of a successor-binding payload (`system-manifest/1` §9).
pub const SUCCESSOR_BINDING_PROFILE: &str = "system-manifest/1:successor-binding";

/// FIPS 204 ML-DSA-65 pkEncode length.
const MLDSA65_PUBKEY_LEN: usize = 1952;

/// Members a statement MUST carry (`system-foundation/1` §6).
const REQUIRED_FIELDS: [&str; 11] = [
    "foundation_profile_id",
    "foundation_statement_id",
    "system_id",
    "system_root_fingerprint",
    "system_manifest",
    "root_fingerprint_derivation",
    "system_domain_capacity_key_p256_b64",
    "system_domain_capacity_key_mldsa_b64",
    "published_rules_versions",
    "statement_issued_at",
    "statement_signatures",
];

/// Members a statement MAY carry besides the required ones
/// (`system-foundation/1` §6). Any other member rejects the statement.
const OPTIONAL_FIELDS: [&str; 2] = ["publication_refs", "successor_binding_observations"];

/// The members of a composite signature object (`composite-signature/1` §8).
const COMPOSITE_FIELDS: [&str; 3] = ["alg", "mode", "signatures"];

/// The canonical unsigned statement payload, with no additional members
/// (`system-foundation/1` §9). JCS sorts the keys, so this order is cosmetic.
const UNSIGNED_PAYLOAD_FIELDS: [&str; 10] = [
    "foundation_profile_id",
    "foundation_statement_id",
    "system_id",
    "system_root_fingerprint",
    "system_manifest",
    "root_fingerprint_derivation",
    "system_domain_capacity_key_p256_b64",
    "system_domain_capacity_key_mldsa_b64",
    "published_rules_versions",
    "statement_issued_at",
];

/// Closed schemas of `system-manifest/1` §6 and §7.8.
const MANIFEST_FIELDS: [&str; 4] = [
    "manifest_profile_id",
    "system_id",
    "manifest_sequence",
    "entries",
];
const ENTRY_FIELDS: [&str; 10] = [
    "kid",
    "algorithm",
    "quorum",
    "members",
    "valid_from",
    "valid_until",
    "predecessor_kid",
    "successor_kid",
    "predecessor_signatures",
    "predecessor_manifest_fingerprint",
];
const QUORUM_FIELDS: [&str; 2] = ["k", "n"];
const MEMBER_FIELDS: [&str; 3] = ["member_kid", "public_key_p256_b64", "public_key_mldsa_b64"];
const MEMBER_SIGNATURE_FIELDS: [&str; 2] = ["signer_member_kid", "signature"];

/// The §9 successor-binding payload, and an observation wrapping it.
const SUCCESSOR_BINDING_FIELDS: [&str; 10] = [
    "binding_profile",
    "system_id",
    "predecessor_kid",
    "predecessor_manifest_fingerprint",
    "predecessor_manifest_sequence",
    "successor_kid",
    "successor_algorithm",
    "successor_quorum",
    "successor_members",
    "successor_valid_from",
];
const OBSERVATION_FIELDS: [&str; 2] = ["successor_binding", "predecessor_signatures"];
/// The fields two observations under one index tuple must agree on (§12.5).
const EQUIVOCATION_FIELDS: [&str; 5] = [
    "successor_kid",
    "successor_quorum",
    "successor_members",
    "successor_algorithm",
    "successor_valid_from",
];
/// The §12.5 index tuple.
const INDEX_TUPLE_FIELDS: [&str; 4] = [
    "system_id",
    "predecessor_manifest_fingerprint",
    "predecessor_manifest_sequence",
    "predecessor_kid",
];

/// Why a foundation statement was rejected. Each variant carries the check id
/// the reference verifier reports for the same failure ([`Self::check_id`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FoundationError {
    /// Not parseable, a required member missing, or the wrong profile.
    #[error("FOUNDATION_PROFILE_VALID: {0}")]
    Profile(String),
    /// The statement's `system_id` is not the embedded manifest's.
    #[error("FOUNDATION_SYSTEM_ID_VALID: {0}")]
    SystemId(String),
    /// Derivation literal, embedded bootstrap manifest, or recomputed fingerprint.
    #[error("FOUNDATION_FINGERPRINT_RECOMPUTED: {0}")]
    Fingerprint(String),
    /// Level-1 capacity key material, or the bootstrap quorum over the payload.
    #[error("FOUNDATION_SIGNATURE_VALID: {0}")]
    Signature(String),
    /// A supplied successor-binding observation is not authorized by the
    /// bootstrap entry's quorum, or does not name it as predecessor.
    #[error("FOUNDATION_SUCCESSOR_QUORUM_VALID: {0}")]
    SuccessorQuorum(String),
    /// Two authenticated observations conflict under one index tuple.
    #[error("FOUNDATION_EQUIVOCATION_DETECTED: {0}")]
    Equivocation(String),
    /// A valid statement for a different root than the one pinned.
    #[error(
        "FOUNDATION_BOOTSTRAP_MATCHES_RULES: the statement's bootstrap fingerprint {recomputed} \
         is not the pinned system_root_fingerprint {pinned}"
    )]
    PinnedFingerprint { pinned: String, recomputed: String },
    /// A valid statement for a registered root whose signed payload is not the
    /// registered one: a second statement over the same bootstrap manifest.
    #[error(
        "FOUNDATION_BOOTSTRAP_MATCHES_RULES: the statement's payload digest {carried} \
         is not the registered bootstrap payload digest {registered}"
    )]
    PinnedPayloadDigest { registered: String, carried: String },
    /// A valid statement for the pinned root that is not the registered
    /// bootstrap statement: its `foundation_statement_id` is another.
    #[error(
        "FOUNDATION_BOOTSTRAP_MATCHES_RULES: the statement's foundation_statement_id {carried} \
         is not the registered bootstrap statement {registered}"
    )]
    PinnedStatementId { registered: String, carried: String },
}

/// The bootstrap statements registered for each published system domain:
/// `(system_root_fingerprint, foundation_statement_id, foundation_payload_digest)`,
/// exactly as the domain's registry entry declares them. A root fingerprint pins
/// the key set; the statement id names the bootstrap statement; the payload
/// digest — SHA3-256(JCS(unsigned payload)), the value the quorum signed — pins
/// every signed member of it, so no second statement over the same manifest is
/// ever accepted.
pub const REGISTERED_BOOTSTRAPS: &[(&str, &str, &str)] = &[(
    "24a0ed1bc18463a060fd04ff255244b4512340696997c9c3fc9f3d3f3079f69a",
    "certcrypt.foundation.bootstrap/2026-10-18",
    "d68370b6e6242478c0088a0b4aefa0055bbfba89009f64481157a704ce13468f",
)];

/// The registered `foundation_statement_id` for a pinned root, if the root
/// belongs to a published system domain.
pub fn registered_statement_id(system_root_fingerprint: &str) -> Option<&'static str> {
    REGISTERED_BOOTSTRAPS
        .iter()
        .find(|(fp, _, _)| *fp == system_root_fingerprint)
        .map(|(_, id, _)| *id)
}

/// The registered `foundation_payload_digest` for a pinned root, if the root
/// belongs to a published system domain.
pub fn registered_payload_digest(system_root_fingerprint: &str) -> Option<&'static str> {
    REGISTERED_BOOTSTRAPS
        .iter()
        .find(|(fp, _, _)| *fp == system_root_fingerprint)
        .map(|(_, _, digest)| *digest)
}

impl FoundationError {
    /// The reference verifier's check id for this failure.
    pub fn check_id(&self) -> &'static str {
        match self {
            Self::Profile(_) => "FOUNDATION_PROFILE_VALID",
            Self::SystemId(_) => "FOUNDATION_SYSTEM_ID_VALID",
            Self::Fingerprint(_) => "FOUNDATION_FINGERPRINT_RECOMPUTED",
            Self::Signature(_) => "FOUNDATION_SIGNATURE_VALID",
            Self::SuccessorQuorum(_) => "FOUNDATION_SUCCESSOR_QUORUM_VALID",
            Self::Equivocation(_) => "FOUNDATION_EQUIVOCATION_DETECTED",
            Self::PinnedFingerprint { .. } => "FOUNDATION_BOOTSTRAP_MATCHES_RULES",
            Self::PinnedStatementId { .. } => "FOUNDATION_BOOTSTRAP_MATCHES_RULES",
            Self::PinnedPayloadDigest { .. } => "FOUNDATION_BOOTSTRAP_MATCHES_RULES",
        }
    }
}

/// What a verified statement establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFoundation {
    pub foundation_statement_id: String,
    pub system_id: String,
    /// The bootstrap fingerprint, recomputed as SHA3-256(JCS(system_manifest))
    /// and equal to the carried value (lowercase hex).
    pub system_root_fingerprint: String,
    /// `kid` of the embedded bootstrap entry (the root quorum, not the Level-1 key).
    pub bootstrap_kid: String,
    pub quorum_k: u64,
    pub quorum_n: u64,
    pub published_rules_versions: Vec<String>,
    pub statement_issued_at: String,
    /// SHA3-256(JCS(unsigned payload)) (lowercase hex): the digest the quorum
    /// signed, and the value a registry entry pins as `foundation_payload_digest`.
    pub foundation_payload_digest: String,
    /// Level-1 capacity key, classical component (ECDSA P-256, SEC1 uncompressed).
    pub capacity_key_p256: Vec<u8>,
    /// Level-1 capacity key, post-quantum component (ML-DSA-65 pkEncode).
    pub capacity_key_mldsa: Vec<u8>,
    /// Successor-binding observations supplied with the statement, each
    /// verified against the bootstrap quorum (zero when none were supplied).
    pub successor_observations: usize,
}

/// One bootstrap-entry member: a composite key under the entry's profile.
struct Member {
    member_kid: String,
    p256: Vec<u8>,
    mldsa: Vec<u8>,
}

/// The parts of the validated bootstrap entry the later checks need.
struct BootstrapEntry {
    kid: String,
    algorithm: String,
    k: u64,
    n: u64,
    valid_from: DateTime<Utc>,
    members: Vec<Member>,
}

/// Verify a `system-foundation/1` statement given as JSON bytes.
///
/// Validation sequence (`system-foundation/1` §11, in the reference verifier's
/// order):
/// 1. the statement carries every §6 member, and `foundation_profile_id` is
///    `system-foundation/1`;
/// 2. its `system_id` is the embedded manifest's;
/// 3. `root_fingerprint_derivation` is `sha3-256-system-manifest-jcs-v1`;
/// 4. the embedded manifest is a conforming bootstrap version: closed schema
///    (`system-manifest/1` §6), sequence 0, one entry with every
///    predecessor/successor member and `valid_until` null, the supported
///    composite profile, `2 ≤ k ≤ n`, exactly `n` members with unique
///    `member_kid` and exact component key lengths;
/// 5. SHA3-256(JCS(system_manifest)) equals the carried `system_root_fingerprint`;
/// 6. both Level-1 capacity key components are present and decode to their
///    exact lengths;
/// 7. at least `k` distinct bootstrap members carry a composite signature that
///    verifies over SHA3-256(JCS(unsigned payload)), the payload including the
///    capacity key (`system-manifest/1` §12.3 counting rule);
/// 8. when `successor_binding_observations` is present: each one names the
///    bootstrap entry as predecessor, is a closed §9 payload, and is authorized
///    by at least `k` distinct bootstrap members; then no two of them conflict
///    under one index tuple (§12.5).
///
/// `publication_refs` are provenance only and are not read.
pub fn verify_system_foundation(bytes: &[u8]) -> Result<VerifiedFoundation, FoundationError> {
    let statement: Value = serde_json::from_slice(bytes)
        .map_err(|e| FoundationError::Profile(format!("statement is not valid JSON: {e}")))?;
    verify_system_foundation_value(&statement)
}

/// [`verify_system_foundation`] over an already-parsed JSON value.
pub fn verify_system_foundation_value(
    statement: &Value,
) -> Result<VerifiedFoundation, FoundationError> {
    let obj = statement
        .as_object()
        .ok_or_else(|| FoundationError::Profile("statement is not a JSON object".into()))?;

    // 1. Structural completeness, then the profile.
    let missing: Vec<&str> = REQUIRED_FIELDS
        .iter()
        .copied()
        .filter(|f| match obj.get(*f) {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) => s.is_empty(),
            _ => false,
        })
        .collect();
    if !missing.is_empty() {
        return Err(FoundationError::Profile(format!(
            "statement missing required fields: {}",
            missing.join(", ")
        )));
    }
    let extra: Vec<&str> = obj
        .keys()
        .map(String::as_str)
        .filter(|k| !REQUIRED_FIELDS.contains(k) && !OPTIONAL_FIELDS.contains(k))
        .collect();
    if !extra.is_empty() {
        return Err(FoundationError::Profile(format!(
            "statement carries members system-foundation/1 does not define: {}",
            extra.join(", ")
        )));
    }
    if !obj["foundation_statement_id"]
        .as_str()
        .is_some_and(is_statement_id)
    {
        return Err(FoundationError::Profile(
            "foundation_statement_id must be 1-128 characters of A-Z a-z 0-9 . _ / -".into(),
        ));
    }
    if obj["statement_issued_at"]
        .as_str()
        .is_none_or(|t| parse_rfc3339_utc(t).is_none())
    {
        return Err(FoundationError::Profile(
            "statement_issued_at must be an RFC 3339 UTC timestamp ending in Z".into(),
        ));
    }
    if obj["foundation_profile_id"].as_str() != Some(FOUNDATION_PROFILE) {
        return Err(FoundationError::Profile(format!(
            "foundation_profile_id must be {FOUNDATION_PROFILE:?}, got {}",
            obj["foundation_profile_id"]
        )));
    }
    let foundation_statement_id = obj["foundation_statement_id"].as_str().ok_or_else(|| {
        FoundationError::Profile("foundation_statement_id is not a string".into())
    })?;
    let published_rules_versions = obj["published_rules_versions"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| {
            FoundationError::Profile("published_rules_versions is not an array of strings".into())
        })?;
    let statement_issued_at = obj["statement_issued_at"]
        .as_str()
        .ok_or_else(|| FoundationError::Profile("statement_issued_at is not a string".into()))?;

    // 2. system_id: a non-empty ASCII string, the embedded manifest's own.
    let system_id = non_empty_ascii(&obj["system_id"]).ok_or_else(|| {
        FoundationError::SystemId("system_id is not a non-empty ASCII string".into())
    })?;
    let manifest = &obj["system_manifest"];
    if let Some(manifest_system_id) = manifest.get("system_id").and_then(Value::as_str) {
        if manifest_system_id != system_id {
            return Err(FoundationError::SystemId(format!(
                "statement system_id {system_id:?} is not the embedded manifest's \
                 {manifest_system_id:?}"
            )));
        }
    }

    // 3. Derivation literal.
    if obj["root_fingerprint_derivation"].as_str() != Some(ROOT_FINGERPRINT_DERIVATION) {
        return Err(FoundationError::Fingerprint(format!(
            "root_fingerprint_derivation must be {ROOT_FINGERPRINT_DERIVATION:?}, got {}",
            obj["root_fingerprint_derivation"]
        )));
    }

    // 4. The embedded manifest is a conforming bootstrap version.
    let bootstrap =
        validate_bootstrap_manifest(manifest, system_id).map_err(FoundationError::Fingerprint)?;

    // 5. Recompute the bootstrap fingerprint.
    let recomputed = sha3_hex(&jcs(manifest)?);
    let declared = obj["system_root_fingerprint"].as_str().unwrap_or_default();
    if recomputed != declared {
        return Err(FoundationError::Fingerprint(format!(
            "system_root_fingerprint mismatch: recomputed {recomputed}, declared {declared}"
        )));
    }

    // 6. The Level-1 capacity key: both components, exact lengths.
    let capacity_key_p256 = obj["system_domain_capacity_key_p256_b64"]
        .as_str()
        .and_then(strict_b64)
        .ok_or_else(|| {
            FoundationError::Signature(
                "system_domain_capacity_key_p256_b64 is not valid RFC 4648 base64".into(),
            )
        })?;
    let capacity_key_mldsa = obj["system_domain_capacity_key_mldsa_b64"]
        .as_str()
        .and_then(strict_b64)
        .ok_or_else(|| {
            FoundationError::Signature(
                "system_domain_capacity_key_mldsa_b64 is not valid RFC 4648 base64".into(),
            )
        })?;
    if !is_p256_sec1(&capacity_key_p256) || capacity_key_mldsa.len() != MLDSA65_PUBKEY_LEN {
        return Err(FoundationError::Signature(
            "system_domain_capacity_key_* component lengths are invalid under the bootstrap \
             composite profile"
                .into(),
        ));
    }

    // 7. The bootstrap quorum over the unsigned payload.
    let payload_digest = foundation_payload_digest(obj)?;
    let verified = count_quorum(
        &obj["statement_signatures"],
        &bootstrap,
        &payload_digest,
        true,
    )
    .map_err(FoundationError::Signature)?;
    if verified < bootstrap.k {
        return Err(FoundationError::Signature(format!(
            "statement_signatures do not meet the bootstrap quorum: {verified} distinct \
             member(s) verified, require k = {}",
            bootstrap.k
        )));
    }

    // 8. Successor-binding observations, authenticated before they are compared.
    let mut successor_observations = 0;
    if let Some(observations) = obj.get("successor_binding_observations") {
        let list = observations
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or_else(|| {
                FoundationError::SuccessorQuorum(
                    "successor_binding_observations must be a non-empty array when present".into(),
                )
            })?;
        for (i, observation) in list.iter().enumerate() {
            verify_successor_observation(observation, system_id, &bootstrap, &recomputed)
                .map_err(|e| FoundationError::SuccessorQuorum(format!("observation [{i}]: {e}")))?;
        }
        detect_equivocation(list)?;
        successor_observations = list.len();
    }

    Ok(VerifiedFoundation {
        foundation_statement_id: foundation_statement_id.to_owned(),
        system_id: system_id.to_owned(),
        system_root_fingerprint: recomputed,
        bootstrap_kid: bootstrap.kid,
        quorum_k: bootstrap.k,
        quorum_n: bootstrap.n,
        published_rules_versions,
        statement_issued_at: statement_issued_at.to_owned(),
        foundation_payload_digest: payload_digest,
        capacity_key_p256,
        capacity_key_mldsa,
        successor_observations,
    })
}

/// SHA3-256(UTF-8(JCS(payload))) of the canonical unsigned statement payload
/// (`system-foundation/1` §9): exactly the ten payload members, taken from the
/// statement as they are. Absent members are carried as `null`, which never
/// matches what was signed.
pub fn foundation_payload_digest(
    statement: &Map<String, Value>,
) -> Result<String, FoundationError> {
    let payload: Map<String, Value> = UNSIGNED_PAYLOAD_FIELDS
        .iter()
        .map(|f| {
            (
                (*f).to_owned(),
                statement.get(*f).cloned().unwrap_or(Value::Null),
            )
        })
        .collect();
    Ok(sha3_hex(&jcs(&Value::Object(payload))?))
}

/// Validate the embedded manifest as a conforming `system-manifest/1` bootstrap
/// version (`system-foundation/1` §7, `system-manifest/1` §6, §7, §13).
fn validate_bootstrap_manifest(
    manifest: &Value,
    statement_system_id: &str,
) -> Result<BootstrapEntry, String> {
    let m = manifest
        .as_object()
        .filter(|m| has_exactly(m, &MANIFEST_FIELDS))
        .ok_or_else(|| {
            format!(
                "system_manifest must be an object with exactly {}",
                MANIFEST_FIELDS.join(", ")
            )
        })?;
    if m["manifest_profile_id"].as_str() != Some(MANIFEST_PROFILE) {
        return Err(format!(
            "system_manifest.manifest_profile_id must be {MANIFEST_PROFILE:?}, got {}",
            m["manifest_profile_id"]
        ));
    }
    if non_empty_ascii(&m["system_id"]) != Some(statement_system_id) {
        return Err(format!(
            "embedded manifest system_id {} differs from statement system_id {statement_system_id:?}",
            m["system_id"]
        ));
    }
    if m["manifest_sequence"].as_u64() != Some(0) {
        return Err(format!(
            "embedded manifest_sequence MUST be 0 (bootstrap); got {}",
            m["manifest_sequence"]
        ));
    }
    let entries = m["entries"]
        .as_array()
        .filter(|e| e.len() == 1)
        .ok_or_else(|| "embedded entries MUST be an array of length 1 (bootstrap)".to_string())?;
    let e = entries[0]
        .as_object()
        .filter(|e| has_exactly(e, &ENTRY_FIELDS))
        .ok_or_else(|| {
            format!(
                "bootstrap entry must be an object with exactly {}",
                ENTRY_FIELDS.join(", ")
            )
        })?;
    let kid = non_empty_ascii(&e["kid"])
        .ok_or_else(|| "bootstrap entry kid must be a non-empty ASCII string".to_string())?;
    for f in [
        "predecessor_kid",
        "successor_kid",
        "predecessor_signatures",
        "predecessor_manifest_fingerprint",
        "valid_until",
    ] {
        if !e[f].is_null() {
            return Err(
                "bootstrap entry predecessor_kid/successor_kid/predecessor_signatures/\
                 predecessor_manifest_fingerprint/valid_until MUST all be null"
                    .into(),
            );
        }
    }
    let algorithm = e["algorithm"].as_str().unwrap_or_default();
    if algorithm != PROFILE_P256_MLDSA65 {
        return Err(format!(
            "bootstrap entry algorithm {:?} is not the supported composite profile \
             {PROFILE_P256_MLDSA65:?}",
            e["algorithm"]
        ));
    }
    let valid_from = e["valid_from"]
        .as_str()
        .and_then(parse_rfc3339_utc)
        .ok_or_else(|| {
            "bootstrap entry valid_from must be an RFC 3339 UTC timestamp".to_string()
        })?;
    let (k, n) = parse_quorum(&e["quorum"]).ok_or_else(|| {
        format!(
            "bootstrap entry quorum invalid: expected {{k,n}} with 2 ≤ k ≤ n, got {}",
            e["quorum"]
        )
    })?;
    let members =
        parse_members(&e["members"], n).map_err(|err| format!("bootstrap entry {err}"))?;
    Ok(BootstrapEntry {
        kid: kid.to_owned(),
        algorithm: algorithm.to_owned(),
        k,
        n,
        valid_from,
        members,
    })
}

/// `{k, n}` with exactly those members, both integers, `2 ≤ k ≤ n`.
fn parse_quorum(q: &Value) -> Option<(u64, u64)> {
    let q = q.as_object().filter(|q| has_exactly(q, &QUORUM_FIELDS))?;
    let (k, n) = (q["k"].as_u64()?, q["n"].as_u64()?);
    (k >= 2 && k <= n).then_some((k, n))
}

/// Exactly `n` closed-schema members, unique `member_kid`, exact key lengths.
fn parse_members(members: &Value, n: u64) -> Result<Vec<Member>, String> {
    let list = members
        .as_array()
        .filter(|a| a.len() as u64 == n)
        .ok_or_else(|| format!("members must list exactly n ({n}) members"))?;
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(list.len());
    for m in list {
        let m = m
            .as_object()
            .filter(|m| has_exactly(m, &MEMBER_FIELDS))
            .ok_or_else(|| {
                format!(
                    "each member must carry exactly {}",
                    MEMBER_FIELDS.join(", ")
                )
            })?;
        let member_kid = non_empty_ascii(&m["member_kid"])
            .filter(|k| seen.insert(k.to_string()))
            .ok_or_else(|| format!("member_kid {} is missing or not unique", m["member_kid"]))?;
        let p256 = m["public_key_p256_b64"].as_str().and_then(strict_b64);
        let mldsa = m["public_key_mldsa_b64"].as_str().and_then(strict_b64);
        let (Some(p256), Some(mldsa)) = (p256, mldsa) else {
            return Err(format!(
                "member {member_kid:?} has a component public key that is not valid RFC 4648 base64"
            ));
        };
        if !is_p256_sec1(&p256) {
            return Err(format!(
                "member {member_kid:?} public_key_p256_b64 is not a SEC1 uncompressed P-256 point (65 bytes, 0x04)"
            ));
        }
        if mldsa.len() != MLDSA65_PUBKEY_LEN {
            return Err(format!(
                "member {member_kid:?} public_key_mldsa_b64 length {} != {MLDSA65_PUBKEY_LEN}",
                mldsa.len()
            ));
        }
        out.push(Member {
            member_kid: member_kid.to_owned(),
            p256,
            mldsa,
        });
    }
    Ok(out)
}

/// Count the DISTINCT members of `entry` whose composite signature verifies over
/// `digest_hex` (`system-manifest/1` §12.3): a non-member never counts, a
/// repeated signer counts once, a signature that does not verify never counts.
///
/// Each element must be an object with exactly `signer_member_kid` and
/// `signature` (§7.8); anything else is an error, not a skipped element.
/// `require_non_empty` rejects an empty or absent array outright.
fn count_quorum(
    signatures: &Value,
    entry: &BootstrapEntry,
    digest_hex: &str,
    require_non_empty: bool,
) -> Result<u64, String> {
    let list = signatures
        .as_array()
        .ok_or_else(|| "signatures must be an array".to_string())?;
    if require_non_empty && list.is_empty() {
        return Err("signatures missing or empty".into());
    }
    let mut verified: HashSet<&str> = HashSet::new();
    for element in list {
        let element = element
            .as_object()
            .filter(|e| has_exactly(e, &MEMBER_SIGNATURE_FIELDS))
            .ok_or_else(|| {
                format!(
                    "each signature must carry exactly {}",
                    MEMBER_SIGNATURE_FIELDS.join(", ")
                )
            })?;
        let Some(kid) = element["signer_member_kid"].as_str() else {
            continue;
        };
        let Some(member) = entry.members.iter().find(|m| m.member_kid == kid) else {
            continue;
        };
        if verified.contains(member.member_kid.as_str()) {
            continue;
        }
        // The composite object is exactly alg, mode, signatures; any other shape
        // is malformed and never counts.
        if !element["signature"]
            .as_object()
            .is_some_and(|o| has_exactly(o, &COMPOSITE_FIELDS))
        {
            continue;
        }
        let Ok(signature) =
            serde_json::from_value::<CompositeSignatureWire>(element["signature"].clone())
        else {
            continue;
        };
        let keys = CompositePublicKeys {
            classical_pub: &member.p256,
            mldsa_pub: &member.mldsa,
        };
        if verify_composite(&entry.algorithm, digest_hex, &signature, keys).is_ok() {
            verified.insert(member.member_kid.as_str());
        }
    }
    Ok(verified.len() as u64)
}

/// One successor-binding observation against the bootstrap entry, which is the
/// only predecessor this statement establishes (`system-manifest/1` §9, §12.3,
/// §13.5, §13.6).
fn verify_successor_observation(
    observation: &Value,
    system_id: &str,
    predecessor: &BootstrapEntry,
    predecessor_fingerprint: &str,
) -> Result<(), String> {
    let observation = observation
        .as_object()
        .filter(|o| has_exactly(o, &OBSERVATION_FIELDS))
        .ok_or_else(|| {
            format!(
                "must be an object with exactly {}",
                OBSERVATION_FIELDS.join(", ")
            )
        })?;
    let binding_value = &observation["successor_binding"];
    let binding = binding_value
        .as_object()
        .filter(|b| has_exactly(b, &SUCCESSOR_BINDING_FIELDS))
        .ok_or_else(|| {
            "successor_binding does not carry exactly the members of the system-manifest/1 §9 \
             payload"
                .to_string()
        })?;

    // The binding must name the predecessor this statement establishes.
    if binding["binding_profile"].as_str() != Some(SUCCESSOR_BINDING_PROFILE) {
        return Err(format!(
            "binding_profile must be {SUCCESSOR_BINDING_PROFILE:?}"
        ));
    }
    if binding["system_id"].as_str() != Some(system_id) {
        return Err(format!(
            "system_id {} is not the statement's system_id",
            binding["system_id"]
        ));
    }
    if binding["predecessor_kid"].as_str() != Some(predecessor.kid.as_str()) {
        return Err(format!(
            "predecessor_kid {} is not the bootstrap entry {:?}",
            binding["predecessor_kid"], predecessor.kid
        ));
    }
    if binding["predecessor_manifest_fingerprint"].as_str() != Some(predecessor_fingerprint) {
        return Err(
            "predecessor_manifest_fingerprint is not the bootstrap manifest's fingerprint".into(),
        );
    }
    if binding["predecessor_manifest_sequence"].as_u64() != Some(0) {
        return Err("predecessor_manifest_sequence must be 0".into());
    }

    // The successor quorum the predecessor authorizes (§7.3, §9, §13.5).
    if binding["successor_algorithm"].as_str() != Some(PROFILE_P256_MLDSA65) {
        return Err(format!(
            "successor_algorithm {} is not the supported composite profile",
            binding["successor_algorithm"]
        ));
    }
    let successor_kid = binding["successor_kid"]
        .as_str()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| "successor_kid must be a non-empty string".to_string())?;
    if successor_kid == predecessor.kid {
        return Err("successor_kid reuses the predecessor's kid".into());
    }
    let (_, n) = parse_quorum(&binding["successor_quorum"]).ok_or_else(|| {
        format!(
            "successor_quorum must be {{k,n}} with 2 ≤ k ≤ n, got {}",
            binding["successor_quorum"]
        )
    })?;
    parse_members(&binding["successor_members"], n).map_err(|e| format!("successor {e}"))?;
    let successor_valid_from = binding["successor_valid_from"]
        .as_str()
        .and_then(parse_rfc3339_utc)
        .ok_or_else(|| "successor_valid_from must be an RFC 3339 UTC timestamp".to_string())?;
    if successor_valid_from <= predecessor.valid_from {
        return Err(
            "successor_valid_from must be strictly later than the predecessor's valid_from".into(),
        );
    }

    // The quorum rule (§12.3) over SHA3-256(UTF-8(JCS(payload))).
    let digest = sha3_hex(&jcs(binding_value).map_err(|e| e.to_string())?);
    let verified = count_quorum(
        &observation["predecessor_signatures"],
        predecessor,
        &digest,
        false,
    )?;
    if verified < predecessor.k {
        return Err(format!(
            "predecessor quorum not met: {verified} distinct predecessor member(s) verified, \
             require k = {}",
            predecessor.k
        ));
    }
    Ok(())
}

/// Equivocation among AUTHENTICATED observations (`system-manifest/1` §12.5):
/// two bindings under one index tuple that differ in any successor field.
/// Values are compared as JCS bytes, so member order cannot hide or fake a
/// difference.
fn detect_equivocation(observations: &[Value]) -> Result<(), FoundationError> {
    let canon = |v: &Value| jcs(v).unwrap_or_default();
    for (i, a) in observations.iter().enumerate() {
        for b in &observations[i + 1..] {
            let (a, b) = (&a["successor_binding"], &b["successor_binding"]);
            if INDEX_TUPLE_FIELDS.iter().any(|f| a[*f] != b[*f]) {
                continue;
            }
            let differing: Vec<&str> = EQUIVOCATION_FIELDS
                .iter()
                .copied()
                .filter(|f| canon(&a[*f]) != canon(&b[*f]))
                .collect();
            if !differing.is_empty() {
                return Err(FoundationError::Equivocation(format!(
                    "two successor-bindings, each authorized by the predecessor quorum over the \
                     same index tuple, differ in {} — the implicated manifest versions are \
                     terminally invalid (system-manifest/1 §12.5)",
                    differing.join(", ")
                )));
            }
        }
    }
    Ok(())
}

// ------------------------------ resolver ------------------------------

/// The production [`ManifestResolver`]: built from a signed `system-foundation/1`
/// statement, verified before anything is exposed.
///
/// Its view is the pinned bootstrap fingerprint and exactly one key: the
/// Level-1 capacity key the bootstrap quorum signed (`system-foundation/1` §6,
/// §9). The root members are never exposed: they authorize the statement and
/// rotation, not issuer bindings.
///
/// The statement publishes the Level-1 key without a `kid` and without an
/// active interval. It resolves here under [`derive_kid`] of its ML-DSA
/// component — the derivation the minting side applies when it writes
/// `authorization_issuer_kid` — and any other kid is refused as
/// [`ManifestError::UnknownKid`]. The resolved entry carries no interval
/// (`valid_from`/`valid_until` are `None`); the binding's own validity window
/// still applies.
///
/// Successor manifest versions (rotations) are not followed: a fingerprint
/// other than the bootstrap one is unknown to this resolver.
#[derive(Debug, Clone)]
pub struct FoundationManifestResolver {
    foundation: VerifiedFoundation,
    level1: ResolvedManifestEntry,
}

impl FoundationManifestResolver {
    /// Verify `statement` ([`verify_system_foundation`]), require its bootstrap
    /// fingerprint to be `pinned_system_root_fingerprint` and, when the root
    /// belongs to a published system domain, its `foundation_statement_id` to be
    /// `pinned_statement_id` (see [`registered_statement_id`]) and its payload
    /// digest to be the registered one ([`registered_payload_digest`]).
    pub fn from_statement_bytes(
        statement: &[u8],
        pinned_system_root_fingerprint: &str,
        pinned_statement_id: Option<&str>,
    ) -> Result<Self, FoundationError> {
        Self::from_statement_bytes_pinned(
            statement,
            pinned_system_root_fingerprint,
            pinned_statement_id,
            registered_payload_digest(pinned_system_root_fingerprint),
        )
    }

    /// [`Self::from_statement_bytes`] with every pin explicit: for a deployment
    /// whose bootstrap is not one of [`REGISTERED_BOOTSTRAPS`] but declares its
    /// statement id and payload digest the same way a registry entry does.
    pub fn from_statement_bytes_pinned(
        statement: &[u8],
        pinned_system_root_fingerprint: &str,
        pinned_statement_id: Option<&str>,
        pinned_payload_digest: Option<&str>,
    ) -> Result<Self, FoundationError> {
        let foundation = verify_system_foundation(statement)?;
        if foundation.system_root_fingerprint != pinned_system_root_fingerprint {
            return Err(FoundationError::PinnedFingerprint {
                pinned: pinned_system_root_fingerprint.to_owned(),
                recomputed: foundation.system_root_fingerprint,
            });
        }
        if let Some(registered) = pinned_statement_id {
            if foundation.foundation_statement_id != registered {
                return Err(FoundationError::PinnedStatementId {
                    registered: registered.to_owned(),
                    carried: foundation.foundation_statement_id,
                });
            }
        }
        // A pinned root admits one statement: its signed payload is pinned.
        if let Some(registered) = pinned_payload_digest {
            if foundation.foundation_payload_digest != registered {
                return Err(FoundationError::PinnedPayloadDigest {
                    registered: registered.to_owned(),
                    carried: foundation.foundation_payload_digest,
                });
            }
        }
        let level1 = ResolvedManifestEntry {
            kid: derive_kid(&foundation.capacity_key_mldsa),
            algorithm: PROFILE_P256_MLDSA65.to_owned(),
            public_key: foundation.capacity_key_mldsa.clone(),
            classical_public_key: foundation.capacity_key_p256.clone(),
            valid_from: None,
            valid_until: None,
        };
        Ok(Self { foundation, level1 })
    }

    /// What the statement established.
    pub fn foundation(&self) -> &VerifiedFoundation {
        &self.foundation
    }

    /// The kid the Level-1 capacity key resolves under.
    pub fn level1_kid(&self) -> &str {
        &self.level1.kid
    }
}

impl ManifestResolver for FoundationManifestResolver {
    fn resolve(
        &self,
        system_root_fingerprint: &str,
        kid: &str,
    ) -> Result<ResolvedManifestEntry, ManifestError> {
        if system_root_fingerprint != self.foundation.system_root_fingerprint {
            return Err(ManifestError::UnknownFingerprint(
                system_root_fingerprint.into(),
            ));
        }
        if kid != self.level1.kid {
            return Err(ManifestError::UnknownKid {
                fingerprint: system_root_fingerprint.into(),
                kid: kid.into(),
            });
        }
        Ok(self.level1.clone())
    }

    fn fingerprint_is_known(&self, system_root_fingerprint: &str) -> bool {
        system_root_fingerprint == self.foundation.system_root_fingerprint
    }
}

// ------------------------------ producer ------------------------------

/// One bootstrap member's composite key pair, for [`sign_foundation_statement`].
pub struct FoundationRootMember<'a> {
    pub member_kid: &'a str,
    pub p256_signing_key: &'a p256::ecdsa::SigningKey,
    pub mldsa_public_key: &'a [u8],
    pub mldsa_secret_key: &'a [u8],
}

/// The unsigned content of a statement, for [`sign_foundation_statement`].
pub struct FoundationStatementInput<'a> {
    pub foundation_statement_id: &'a str,
    pub system_id: &'a str,
    pub bootstrap_kid: &'a str,
    /// RFC 3339 UTC, e.g. `2026-01-01T00:00:00Z`.
    pub bootstrap_valid_from: &'a str,
    pub quorum_k: u64,
    pub members: &'a [FoundationRootMember<'a>],
    pub capacity_key_p256: &'a [u8],
    pub capacity_key_mldsa: &'a [u8],
    pub published_rules_versions: &'a [String],
    pub statement_issued_at: &'a str,
}

/// Assemble a bootstrap manifest and a `system-foundation/1` statement over it,
/// signed by the first `quorum_k` members. Producer and verifier share the
/// canonicalization in this module; the conformance vectors, produced
/// independently, are what pin it.
///
/// For tests and local development material. A real deployment's statement is
/// the one its key ceremony emits.
pub fn sign_foundation_statement(input: &FoundationStatementInput<'_>) -> VerifyResult<Value> {
    let members: Vec<Value> = input
        .members
        .iter()
        .map(|m| {
            serde_json::json!({
                "member_kid": m.member_kid,
                "public_key_p256_b64": B64.encode(ecdsa_p256::public_key_sec1(m.p256_signing_key, false)),
                "public_key_mldsa_b64": B64.encode(m.mldsa_public_key),
            })
        })
        .collect();
    let manifest = serde_json::json!({
        "manifest_profile_id": MANIFEST_PROFILE,
        "system_id": input.system_id,
        "manifest_sequence": 0,
        "entries": [{
            "kid": input.bootstrap_kid,
            "algorithm": PROFILE_P256_MLDSA65,
            "quorum": { "k": input.quorum_k, "n": input.members.len() },
            "members": members,
            "valid_from": input.bootstrap_valid_from,
            "valid_until": null,
            "predecessor_kid": null,
            "successor_kid": null,
            "predecessor_signatures": null,
            "predecessor_manifest_fingerprint": null,
        }],
    });
    let canonical = serde_jcs::to_vec(&manifest)
        .map_err(|e| crate::VerifyError::CompositeMaterial(format!("JCS(manifest): {e}")))?;
    let fingerprint = sha3_hex(&canonical);
    let mut statement = serde_json::json!({
        "foundation_profile_id": FOUNDATION_PROFILE,
        "foundation_statement_id": input.foundation_statement_id,
        "system_id": input.system_id,
        "system_root_fingerprint": fingerprint,
        "system_manifest": manifest,
        "root_fingerprint_derivation": ROOT_FINGERPRINT_DERIVATION,
        "system_domain_capacity_key_p256_b64": B64.encode(input.capacity_key_p256),
        "system_domain_capacity_key_mldsa_b64": B64.encode(input.capacity_key_mldsa),
        "published_rules_versions": input.published_rules_versions,
        "statement_issued_at": input.statement_issued_at,
    });
    let digest = foundation_payload_digest(statement.as_object().expect("object"))
        .map_err(|e| crate::VerifyError::CompositeMaterial(e.to_string()))?;
    let mut signatures = Vec::new();
    for m in input.members.iter().take(input.quorum_k as usize) {
        let sig =
            crate::composite::composite_sign_p256(&digest, m.p256_signing_key, m.mldsa_secret_key)?;
        signatures.push(serde_json::json!({
            "signer_member_kid": m.member_kid,
            "signature": sig,
        }));
    }
    statement["statement_signatures"] = Value::Array(signatures);
    Ok(statement)
}

// ------------------------------ helpers ------------------------------

fn has_exactly(obj: &Map<String, Value>, fields: &[&str]) -> bool {
    obj.len() == fields.len() && fields.iter().all(|f| obj.contains_key(*f))
}

fn non_empty_ascii(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| !s.is_empty() && s.is_ascii())
}

/// Strict RFC 4648 base64 (standard alphabet, canonical padding), non-empty.
fn strict_b64(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    B64.decode(s).ok()
}

/// SEC1 uncompressed P-256 (65 bytes, 0x04): the one encoding of every P-256
/// key field (`system-manifest/1` §7.3, `system-foundation/1` §6).
fn is_p256_sec1(b: &[u8]) -> bool {
    b.len() == 65 && b[0] == 0x04
}

/// `foundation_statement_id` format (`system-foundation/1` §6).
fn is_statement_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
}

/// RFC 3339 with an explicit `Z` zone (`system-manifest/1` §7.4):
/// `YYYY-MM-DDTHH:MM:SS(.fraction)?Z`.
fn parse_rfc3339_utc(s: &str) -> Option<DateTime<Utc>> {
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    let shape = b.len() >= 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && b[b.len() - 1] == b'Z'
        && (b.len() == 20 || (b[19] == b'.' && b.len() > 21 && digits(20..b.len() - 1)));
    if !shape {
        return None;
    }
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn jcs(v: &Value) -> Result<Vec<u8>, FoundationError> {
    serde_jcs::to_vec(v).map_err(|e| FoundationError::Profile(format!("JCS canonicalization: {e}")))
}

fn sha3_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mldsa;

    struct Keys {
        p256: p256::ecdsa::SigningKey,
        mldsa_pk: Vec<u8>,
        mldsa_sk: Vec<u8>,
    }

    fn keys(seed: u8) -> Keys {
        let s = [seed; 32];
        let (mldsa_pk, mldsa_sk) = mldsa::keypair_from_seed(&s).unwrap();
        Keys {
            p256: ecdsa_p256::signing_key_from_seed(&s),
            mldsa_pk,
            mldsa_sk,
        }
    }

    /// A 2-of-3 statement signed by m0 and m1, with capacity key `cap`.
    fn statement(cap: &Keys) -> Value {
        let (a, b, c) = (keys(1), keys(2), keys(3));
        let members = [
            FoundationRootMember {
                member_kid: "m0",
                p256_signing_key: &a.p256,
                mldsa_public_key: &a.mldsa_pk,
                mldsa_secret_key: &a.mldsa_sk,
            },
            FoundationRootMember {
                member_kid: "m1",
                p256_signing_key: &b.p256,
                mldsa_public_key: &b.mldsa_pk,
                mldsa_secret_key: &b.mldsa_sk,
            },
            FoundationRootMember {
                member_kid: "m2",
                p256_signing_key: &c.p256,
                mldsa_public_key: &c.mldsa_pk,
                mldsa_secret_key: &c.mldsa_sk,
            },
        ];
        sign_foundation_statement(&FoundationStatementInput {
            foundation_statement_id: "unit-test",
            system_id: "certcrypt",
            bootstrap_kid: "root-1",
            bootstrap_valid_from: "2026-01-01T00:00:00Z",
            quorum_k: 2,
            members: &members,
            capacity_key_p256: &ecdsa_p256::public_key_sec1(&cap.p256, false),
            capacity_key_mldsa: &cap.mldsa_pk,
            published_rules_versions: &["rules/test".to_string()],
            statement_issued_at: "2026-01-02T00:00:00Z",
        })
        .unwrap()
    }

    fn bytes(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    #[test]
    fn signed_statement_verifies_and_exposes_the_capacity_key() {
        let cap = keys(9);
        let s = statement(&cap);
        let srf = s["system_root_fingerprint"].as_str().unwrap().to_owned();
        let r = FoundationManifestResolver::from_statement_bytes(&bytes(&s), &srf, None).unwrap();
        assert_eq!(r.foundation().quorum_k, 2);
        assert_eq!(r.foundation().quorum_n, 3);
        assert_eq!(r.level1_kid(), derive_kid(&cap.mldsa_pk));
        let e = r.resolve(&srf, &derive_kid(&cap.mldsa_pk)).unwrap();
        assert_eq!(e.public_key, cap.mldsa_pk);
        assert_eq!(
            e.classical_public_key,
            ecdsa_p256::public_key_sec1(&cap.p256, false)
        );
        assert!(e.valid_from.is_none() && e.valid_until.is_none());
        assert!(r.fingerprint_is_known(&srf));
    }

    #[test]
    fn resolution_misses_are_distinct_and_never_expand_the_view() {
        let cap = keys(9);
        let s = statement(&cap);
        let srf = s["system_root_fingerprint"].as_str().unwrap().to_owned();
        let r = FoundationManifestResolver::from_statement_bytes(&bytes(&s), &srf, None).unwrap();
        let kid = r.level1_kid().to_owned();
        assert!(matches!(
            r.resolve(&"cc".repeat(32), &kid),
            Err(ManifestError::UnknownFingerprint(_))
        ));
        assert!(matches!(
            r.resolve(&srf, "root-1"),
            Err(ManifestError::UnknownKid { .. })
        ));
        assert!(matches!(
            r.resolve(&srf, "m0"),
            Err(ManifestError::UnknownKid { .. })
        ));
        assert!(!r.fingerprint_is_known(&"cc".repeat(32)));
    }

    #[test]
    fn a_different_pin_is_refused() {
        let s = statement(&keys(9));
        let err =
            FoundationManifestResolver::from_statement_bytes(&bytes(&s), &"ab".repeat(32), None)
                .unwrap_err();
        assert_eq!(err.check_id(), "FOUNDATION_BOOTSTRAP_MATCHES_RULES");
    }

    #[test]
    fn the_right_root_under_another_statement_id_is_refused() {
        let s = statement(&keys(9));
        let srf = s["system_root_fingerprint"].as_str().unwrap().to_owned();
        let err = FoundationManifestResolver::from_statement_bytes(
            &bytes(&s),
            &srf,
            Some("another-statement"),
        )
        .unwrap_err();
        assert!(matches!(err, FoundationError::PinnedStatementId { .. }));
        assert_eq!(err.check_id(), "FOUNDATION_BOOTSTRAP_MATCHES_RULES");
        assert!(FoundationManifestResolver::from_statement_bytes(
            &bytes(&s),
            &srf,
            Some("unit-test")
        )
        .is_ok());
    }

    #[test]
    fn the_published_root_is_registered_with_its_signed_statement_id() {
        assert_eq!(
            registered_statement_id(
                "24a0ed1bc18463a060fd04ff255244b4512340696997c9c3fc9f3d3f3079f69a"
            ),
            Some("certcrypt.foundation.bootstrap/2026-10-18")
        );
        assert_eq!(registered_statement_id(&"ab".repeat(32)), None);
    }

    #[test]
    fn the_published_root_is_registered_with_its_payload_digest() {
        assert_eq!(
            registered_payload_digest(
                "24a0ed1bc18463a060fd04ff255244b4512340696997c9c3fc9f3d3f3079f69a"
            ),
            Some("d68370b6e6242478c0088a0b4aefa0055bbfba89009f64481157a704ce13468f")
        );
        assert_eq!(registered_payload_digest(&"ab".repeat(32)), None);
        let s = statement(&keys(9));
        let v = verify_system_foundation(&bytes(&s)).unwrap();
        assert_eq!(
            v.foundation_payload_digest,
            foundation_payload_digest(s.as_object().unwrap()).unwrap()
        );
    }

    #[test]
    fn the_statement_shape_is_closed_and_formatted() {
        let profile = |s: &Value| verify_system_foundation(&bytes(s)).unwrap_err().check_id();
        let mut s = statement(&keys(9));
        s["statement_note"] = Value::String("x".into());
        assert_eq!(profile(&s), "FOUNDATION_PROFILE_VALID");
        let mut s = statement(&keys(9));
        s["foundation_statement_id"] = Value::String("has space".into());
        assert_eq!(profile(&s), "FOUNDATION_PROFILE_VALID");
        let mut s = statement(&keys(9));
        s["statement_issued_at"] = Value::String("2026-01-01T00:00:00+00:00".into());
        assert_eq!(profile(&s), "FOUNDATION_PROFILE_VALID");
    }

    #[test]
    fn a_compressed_p256_key_is_malformed() {
        let mut s = statement(&keys(9));
        let raw = B64
            .decode(s["system_domain_capacity_key_p256_b64"].as_str().unwrap())
            .unwrap();
        let mut compressed = vec![if raw[64] & 1 == 1 { 0x03 } else { 0x02 }];
        compressed.extend_from_slice(&raw[1..33]);
        s["system_domain_capacity_key_p256_b64"] = Value::String(B64.encode(compressed));
        assert_eq!(
            verify_system_foundation(&bytes(&s)).unwrap_err().check_id(),
            "FOUNDATION_SIGNATURE_VALID"
        );
    }

    #[test]
    fn a_substituted_capacity_key_breaks_the_quorum() {
        let mut s = statement(&keys(9));
        let other = keys(10);
        s["system_domain_capacity_key_mldsa_b64"] = Value::String(B64.encode(&other.mldsa_pk));
        let err = verify_system_foundation(&bytes(&s)).unwrap_err();
        assert_eq!(err.check_id(), "FOUNDATION_SIGNATURE_VALID");
    }

    #[test]
    fn one_signature_is_below_a_two_of_three_quorum() {
        let mut s = statement(&keys(9));
        s["statement_signatures"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        assert_eq!(
            verify_system_foundation(&bytes(&s)).unwrap_err().check_id(),
            "FOUNDATION_SIGNATURE_VALID"
        );
    }

    #[test]
    fn a_repeated_signer_counts_once() {
        let mut s = statement(&keys(9));
        let sigs = s["statement_signatures"].as_array_mut().unwrap();
        let first = sigs[0].clone();
        sigs[1] = first;
        assert_eq!(
            verify_system_foundation(&bytes(&s)).unwrap_err().check_id(),
            "FOUNDATION_SIGNATURE_VALID"
        );
    }

    #[test]
    fn a_malformed_signature_element_rejects() {
        let mut s = statement(&keys(9));
        s["statement_signatures"]
            .as_array_mut()
            .unwrap()
            .push(Value::Null);
        assert_eq!(
            verify_system_foundation(&bytes(&s)).unwrap_err().check_id(),
            "FOUNDATION_SIGNATURE_VALID"
        );
    }

    #[test]
    fn the_manifest_schema_is_closed() {
        // An extra member also changes the fingerprint; the schema check runs first.
        let mut s = statement(&keys(9));
        s["system_manifest"]["entries"][0]["note"] = Value::String("extra".into());
        assert_eq!(
            verify_system_foundation(&bytes(&s)).unwrap_err().check_id(),
            "FOUNDATION_FINGERPRINT_RECOMPUTED"
        );
        let mut s = statement(&keys(9));
        s["system_manifest"]["extra"] = Value::Bool(true);
        assert_eq!(
            verify_system_foundation(&bytes(&s)).unwrap_err().check_id(),
            "FOUNDATION_FINGERPRINT_RECOMPUTED"
        );
    }

    #[test]
    fn missing_members_and_wrong_profile_reject() {
        let mut s = statement(&keys(9));
        s.as_object_mut()
            .unwrap()
            .remove("system_domain_capacity_key_p256_b64");
        assert_eq!(
            verify_system_foundation(&bytes(&s)).unwrap_err().check_id(),
            "FOUNDATION_PROFILE_VALID"
        );
        let mut s = statement(&keys(9));
        s["foundation_profile_id"] = Value::String("system-foundation/2".into());
        assert_eq!(
            verify_system_foundation(&bytes(&s)).unwrap_err().check_id(),
            "FOUNDATION_PROFILE_VALID"
        );
        assert_eq!(
            verify_system_foundation(b"not json")
                .unwrap_err()
                .check_id(),
            "FOUNDATION_PROFILE_VALID"
        );
    }

    #[test]
    fn publication_refs_do_not_affect_validity() {
        let mut s = statement(&keys(9));
        s["publication_refs"] =
            serde_json::json!([{ "publication_profile": "x", "publication_reference": "y" }]);
        verify_system_foundation(&bytes(&s)).unwrap();
    }

    #[test]
    fn rfc3339_shape() {
        assert!(parse_rfc3339_utc("2026-01-01T00:00:00Z").is_some());
        assert!(parse_rfc3339_utc("2026-01-01T00:00:00.5Z").is_some());
        assert!(parse_rfc3339_utc("2026-01-01T00:00:00+00:00").is_none());
        assert!(parse_rfc3339_utc("2026-01-01T00:00:00.Z").is_none());
        assert!(parse_rfc3339_utc("2026-01-01 00:00:00Z").is_none());
    }
}
