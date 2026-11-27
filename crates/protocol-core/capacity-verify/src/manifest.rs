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

//! `system-manifest/1` resolver abstraction.
//!
//! Capacity-chain verification needs to resolve two kinds of identity material
//! offline:
//!
//! - the **system_root_fingerprint** of the `capacity.commitment/1` envelope
//!   (and of the referenced `capacity.holder-authorization/1`) MUST equal
//!   either the bootstrap fingerprint of the active manifest or the digest of
//!   a manifest version reachable by valid extension validation.
//!
//! - the **Level-1 signing key** (`authorization_issuer.kid`) used to sign
//!   `capacity.holder-authorization/1`. The resolver answers
//!   `(fingerprint, kid) -> public_key_bytes`.
//!
//! Two implementations satisfy the trait:
//!
//! - [`crate::foundation::FoundationManifestResolver`] — built from a signed
//!   `system-foundation/1` statement, which it verifies fail-closed against a
//!   pinned fingerprint before exposing any key. This is the resolver for a
//!   party that does NOT hold the system-domain keys (a node, a verifier).
//! - [`StaticManifestResolver`] — an in-memory table filled by its caller. For
//!   the process that holds the system-domain keys itself and seats its own
//!   public keys, and for tests. It verifies nothing about where its entries
//!   came from.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Outcome of a successful `(system_root_fingerprint, kid)` resolution.
#[derive(Debug, Clone)]
pub struct ResolvedManifestEntry {
    pub kid: String,
    pub algorithm: String,
    /// ML-DSA-65 component public key (the system-domain composite key, `composite-signature/1`).
    pub public_key: Vec<u8>,
    /// Classical component public key of the composite system-domain key:
    /// ECDSA P-256 SEC1 (canonical profile) or Ed25519 raw-32 (additional).
    /// Empty for non-composite (e.g. credential) entries.
    pub classical_public_key: Vec<u8>,
    /// Inclusive lower bound of the entry's active interval, when the material
    /// the resolver was built from declares one. `None`: no bound declared.
    pub valid_from: Option<DateTime<Utc>>,
    /// Exclusive upper bound of the entry's active interval (half-open,
    /// `system-manifest/1` §7.5), when declared. `None`: no bound declared.
    pub valid_until: Option<DateTime<Utc>>,
}

impl ResolvedManifestEntry {
    /// Whether this entry was the active signing entry at `instant`: inside its
    /// half-open interval `[valid_from, valid_until)` (`system-manifest/1`
    /// §7.5). A bound the resolver's material does not declare does not
    /// restrict.
    ///
    /// What a Level-1 entry signs is a holder authorization, and the instant
    /// it is checked at is that authorization's own `valid_from` — when it says
    /// it was issued. A key rotated out keeps verifying what it signed while it
    /// was active (§1, longevity), and signs nothing valid after: an
    /// authorization starting after the entry's `valid_until` is refused
    /// however well it verifies.
    pub fn active_at(&self, instant: DateTime<Utc>) -> bool {
        self.valid_from.is_none_or(|from| from <= instant)
            && self.valid_until.is_none_or(|until| instant < until)
    }

    /// [`Self::active_at`] for an RFC 3339 instant; an unparseable one is never
    /// active (fail-closed).
    pub fn active_at_rfc3339(&self, instant: &str) -> bool {
        DateTime::parse_from_rfc3339(instant)
            .map(|t| self.active_at(t.with_timezone(&Utc)))
            .unwrap_or(false)
    }
}

/// Errors a manifest resolver may surface to the verifier.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ManifestError {
    #[error("system_root_fingerprint {0:?} unknown to this resolver")]
    UnknownFingerprint(String),
    #[error("kid {kid:?} not present at fingerprint {fingerprint:?}")]
    UnknownKid { fingerprint: String, kid: String },
}

pub trait ManifestResolver: Send + Sync {
    /// Resolve `(fingerprint, kid)` to the manifest entry that signed at that
    /// kid. Implementations MUST refuse to expand the manifest on the fly:
    /// only entries already present in the resolver's view may be returned.
    fn resolve(
        &self,
        system_root_fingerprint: &str,
        kid: &str,
    ) -> Result<ResolvedManifestEntry, ManifestError>;

    /// Confirm that a fingerprint corresponds either to the bootstrap manifest
    /// or to a manifest version reachable by valid extension validation, as far
    /// as this resolver's view goes.
    fn fingerprint_is_known(&self, system_root_fingerprint: &str) -> bool;
}

/// The kid a system-domain key is resolved under: `dev:` followed by the
/// unpadded standard base64 of the first 16 bytes of SHA3-256(public_key).
///
/// Sixteen bytes, not thirty-two: the kid identifies, it does not authenticate —
/// the signature does that. The party that mints Level-1 bindings writes this
/// value into `authorization_issuer_kid`, and every resolver looks it up the
/// same way, so it lives here, once, and must not drift.
pub fn derive_kid(public_key: &[u8]) -> String {
    let digest = Sha3_256::digest(public_key);
    format!(
        "dev:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(&digest[..16])
    )
}

// ---------------------------- static resolver ----------------------------

/// In-memory resolver whose entries are inserted by its caller.
///
/// It authenticates nothing: whatever is inserted resolves. That is right for a
/// process that holds the system-domain keys and seats its own public keys, and
/// for tests. A party that has to TRUST the system domain's keys rather than
/// hold them uses [`crate::foundation::FoundationManifestResolver`] instead.
#[derive(Debug, Default, Clone)]
pub struct StaticManifestResolver {
    /// Map: `system_root_fingerprint -> kid -> entry`.
    by_fingerprint: HashMap<String, HashMap<String, ResolvedManifestEntry>>,
}

impl StaticManifestResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, system_root_fingerprint: &str, entry: ResolvedManifestEntry) {
        self.by_fingerprint
            .entry(system_root_fingerprint.to_owned())
            .or_default()
            .insert(entry.kid.clone(), entry);
    }
}

impl ManifestResolver for StaticManifestResolver {
    fn resolve(
        &self,
        system_root_fingerprint: &str,
        kid: &str,
    ) -> Result<ResolvedManifestEntry, ManifestError> {
        let by_kid = self
            .by_fingerprint
            .get(system_root_fingerprint)
            .ok_or_else(|| ManifestError::UnknownFingerprint(system_root_fingerprint.into()))?;
        by_kid
            .get(kid)
            .cloned()
            .ok_or_else(|| ManifestError::UnknownKid {
                fingerprint: system_root_fingerprint.into(),
                kid: kid.into(),
            })
    }

    fn fingerprint_is_known(&self, system_root_fingerprint: &str) -> bool {
        self.by_fingerprint.contains_key(system_root_fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn entry(from: Option<i32>, until: Option<i32>) -> ResolvedManifestEntry {
        let at = |y| Utc.with_ymd_and_hms(y, 1, 1, 0, 0, 0).unwrap();
        ResolvedManifestEntry {
            kid: "k".into(),
            algorithm: "a".into(),
            public_key: Vec::new(),
            classical_public_key: Vec::new(),
            valid_from: from.map(at),
            valid_until: until.map(at),
        }
    }

    #[test]
    fn the_active_interval_is_half_open() {
        let e = entry(Some(2020), Some(2021));
        assert!(
            e.active_at_rfc3339("2020-01-01T00:00:00Z"),
            "valid_from is inside"
        );
        assert!(e.active_at_rfc3339("2020-06-01T00:00:00Z"));
        assert!(
            !e.active_at_rfc3339("2021-01-01T00:00:00Z"),
            "valid_until belongs to the successor"
        );
        assert!(!e.active_at_rfc3339("2019-12-31T23:59:59Z"));
        // An authorization claiming to start after the key was rotated out.
        assert!(!e.active_at_rfc3339("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn an_undeclared_bound_does_not_restrict_and_garbage_never_passes() {
        assert!(entry(None, None).active_at_rfc3339("2026-01-01T00:00:00Z"));
        assert!(entry(Some(2020), None).active_at_rfc3339("2099-01-01T00:00:00Z"));
        assert!(!entry(None, None).active_at_rfc3339("yesterday"));
    }
}
