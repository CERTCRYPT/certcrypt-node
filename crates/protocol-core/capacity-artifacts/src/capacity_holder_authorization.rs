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

//! Level-2 authorization anchor: the system-domain-signed Level-1 binding.
//!
//! CERTCRYPT authorizes a holder by signing a [`Level1AuthorizationBinding`]
//! over the holder's `holder_key_set_root` — a Merkle root over a set of
//! per-operation holder keys — plus the system context and validity window. The
//! binding is carried inside each `capacity.evidence/1` (see
//! [`crate::capacity_evidence`]). This module owns that binding plus the role
//! anchor the issuance endpoint uses; the binding's signature is the composite
//! Level-1 signature carried next to it in the evidence.

use crate::errors::ArtifactError;
use serde::{Deserialize, Serialize};

pub const AUTHORIZED_ROLE: &str = "capacity_commitment_holder";

/// The exact object the **system-domain Level-1 key** signs when CERTCRYPT
/// authorizes a holder's operation-key tree (zero-data mode of
/// `capacity.holder-authorization/1`). It commits to the
/// `holder_key_set_root` plus the system context and validity window — none of
/// which identifies the holder (the root is a Merkle commitment, not a
/// semantic id; the rest is public-by-design). The root is the same for every
/// certificate under the authorization.
///
/// This is NOT a standalone artifact: it is the signed sub-object inside the
/// zero-data `capacity.holder-authorization/1`, carried in the evidence's
/// `level1_binding` field. It therefore has no version tag of its own — its
/// version is the authorization's. (It lives in this crate, with the other
/// CERTCRYPT-signed artifact types: the issuance service signs it; node/SDK reuse it.)
///
/// Field order is the canonical signing order — **insertion-ordered, NOT JCS**.
/// `signing_bytes` therefore uses `serde_json::to_vec` (preserving struct field
/// order), deliberately NOT `canonical::canonicalize` (which would sort keys).
/// A divergent byte breaks the verifier's Level-1 check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Level1AuthorizationBinding {
    pub system_id: String,
    pub rules_version: String,
    pub system_root_fingerprint: String,
    pub authorized_role: String,
    pub authorization_issuer_kid: String,
    pub valid_from: String,
    pub valid_until: String,
    pub holder_key_set_root: String,
}

impl Level1AuthorizationBinding {
    /// Canonical bytes the system-domain Level-1 key signs. Insertion-ordered
    /// (not JCS) — every producer and verifier must match these bytes exactly.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        Ok(serde_json::to_vec(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level1_binding_rejects_an_additional_member() {
        let value = serde_json::json!({
            "system_id": "certcrypt",
            "rules_version": "rules/conformance",
            "system_root_fingerprint": "ab".repeat(32),
            "authorized_role": AUTHORIZED_ROLE,
            "authorization_issuer_kid": "system-domain-kid-1",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "holder_key_set_root": "cd".repeat(32),
            "unexpected": true
        });
        assert!(serde_json::from_value::<Level1AuthorizationBinding>(value).is_err());
    }

    fn sample_binding() -> Level1AuthorizationBinding {
        Level1AuthorizationBinding {
            system_id: "certcrypt".into(),
            rules_version: "rules/conformance".into(),
            system_root_fingerprint:
                "abababababababababababababababababababababababababababababababab".into(),
            authorized_role: AUTHORIZED_ROLE.into(),
            authorization_issuer_kid: "system-domain-kid-1".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
            holder_key_set_root: "1111111111111111111111111111111111111111111111111111111111111111"
                .into(),
        }
    }

    #[test]
    fn signing_bytes_are_insertion_ordered_and_deterministic() {
        let b = sample_binding();
        let a = b.signing_bytes().unwrap();
        let c = b.signing_bytes().unwrap();
        assert_eq!(a, c, "signing bytes are deterministic");
        // Insertion order (NOT JCS): system_id appears before rules_version in
        // the serialized bytes, even though JCS would sort r before s.
        let s = String::from_utf8(a).unwrap();
        let i_system = s.find("system_id").unwrap();
        let i_rules = s.find("rules_version").unwrap();
        assert!(
            i_system < i_rules,
            "field order must be insertion order, not JCS"
        );
    }
}
