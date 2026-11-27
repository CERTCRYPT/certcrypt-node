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

//! Wire-format type for `operator.recognition/1` — the credential CERTCRYPT's
//! system-domain signs to recognize a node operator under CERTCRYPT rules.
//!
//! Mirrors `capacity.holder-authorization/1` structurally (same JCS discipline,
//! same two-pass id). The node presents this credential, with a fresh
//! possession proof by the operator key, to the fixation service on every
//! submission and every domain-binding registration; the fixation service is
//! the only party that checks it. For the issuer the node is a transport.
//!
//! Claims boundary: recognition is an "identity recognised under CERTCRYPT
//! rules" — NEVER "approved/certified". No tiers, badges, metrics or commercial
//! categories in this payload.
//!
//! Signed by a DEDICATED credential sub-key, NOT the proof /
//! holder-authorization signing key. The signature kid resolves the sub-key's
//! public key via the manifest resolver, the same way Level-1 keys resolve.

use crate::canonical::{canonical_digest_hex, canonicalize};
use crate::errors::ArtifactError;
use base64::engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NP};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const RECOGNITION_ARTIFACT_TYPE: &str = "operator.recognition/1";
pub const OPERATOR_KEY_ALG_ACTIVE: &str = "ml-dsa-65-fips204-v1";
pub const SIGNATURE_ALG_ACTIVE: &str = "ml-dsa-65-fips204-v1";
/// Canonical phrasing for any rendering of this surface.
pub const CANONICAL_RECOGNITION_PHRASE: &str = "identity recognised under CERTCRYPT rules";

/// Deterministic operator id from the operator public key: `op:` +
/// STANDARD_NO_PAD(sha3-256(pk)[..16]). MUST match the node's derivation in
/// the operator-id derivation every implementation performs, byte-for-byte, so
/// the issuing side and the verifying side agree.
pub fn derive_operator_id(operator_public_key: &[u8]) -> String {
    let digest = Sha3_256::digest(operator_public_key);
    format!("op:{}", B64_NP.encode(&digest[..16]))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorRecognitionCredentialV1 {
    pub artifact_type: String,
    pub system_id: String,
    pub rules_version: String,
    /// CERTCRYPT's system_root_fingerprint — the anti-bait-and-switch anchor:
    /// the checking party compares it with the fingerprint it knows.
    pub system_root_fingerprint: String,
    pub recognition_id: String,
    pub operator_id: String,
    /// base64 (standard) of the operator's ML-DSA-65 public key. The node proves
    /// possession of the matching secret at presentation.
    pub operator_public_key: String,
    pub operator_key_alg: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// The credential sub-key that signed this. kid resolves the
    /// sub-key public key via the manifest resolver.
    pub recognition_issuer: RecognitionIssuer,
    pub signature: RecognitionSignature,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorRecognitionV1NoIdNoSig<'a> {
    artifact_type: &'a str,
    system_id: &'a str,
    rules_version: &'a str,
    system_root_fingerprint: &'a str,
    operator_id: &'a str,
    operator_public_key: &'a str,
    operator_key_alg: &'a str,
    valid_from: &'a DateTime<Utc>,
    valid_until: &'a DateTime<Utc>,
    recognition_issuer: &'a RecognitionIssuer,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorRecognitionV1NoSig<'a> {
    artifact_type: &'a str,
    system_id: &'a str,
    rules_version: &'a str,
    system_root_fingerprint: &'a str,
    recognition_id: &'a str,
    operator_id: &'a str,
    operator_public_key: &'a str,
    operator_key_alg: &'a str,
    valid_from: &'a DateTime<Utc>,
    valid_until: &'a DateTime<Utc>,
    recognition_issuer: &'a RecognitionIssuer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecognitionIssuer {
    /// Credential sub-key identifier, resolved against the manifest. NOT the
    /// proof/holder-auth kid.
    pub kid: String,
    pub manifest_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecognitionSignature {
    pub signature_alg: String,
    pub signature_b64: String,
}

/// Inputs to build an unsigned credential (the issuance service fills these, then signs).
#[derive(Debug, Clone)]
pub struct RecognitionInputs {
    pub system_root_fingerprint: String,
    pub rules_version: String,
    pub operator_public_key: String,
    pub operator_key_alg: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub recognition_issuer: RecognitionIssuer,
}

impl OperatorRecognitionCredentialV1 {
    /// Pass 1: deterministic recognition_id = SHA3-256(JCS(no-id, no-sig view)).
    /// `operator_id` is derived from the operator public key and included in the
    /// view.
    pub fn compute_recognition_id(
        inputs: &RecognitionInputs,
        operator_id: &str,
    ) -> Result<String, ArtifactError> {
        let view = OperatorRecognitionV1NoIdNoSig {
            artifact_type: RECOGNITION_ARTIFACT_TYPE,
            system_id: super::capacity_commitment::SYSTEM_ID_ACTIVE,
            rules_version: &inputs.rules_version,
            system_root_fingerprint: &inputs.system_root_fingerprint,
            operator_id,
            operator_public_key: &inputs.operator_public_key,
            operator_key_alg: &inputs.operator_key_alg,
            valid_from: &inputs.valid_from,
            valid_until: &inputs.valid_until,
            recognition_issuer: &inputs.recognition_issuer,
        };
        canonical_digest_hex(&view)
    }

    pub fn recompute_recognition_id(&self) -> Result<String, ArtifactError> {
        let view = OperatorRecognitionV1NoIdNoSig {
            artifact_type: &self.artifact_type,
            system_id: &self.system_id,
            rules_version: &self.rules_version,
            system_root_fingerprint: &self.system_root_fingerprint,
            operator_id: &self.operator_id,
            operator_public_key: &self.operator_public_key,
            operator_key_alg: &self.operator_key_alg,
            valid_from: &self.valid_from,
            valid_until: &self.valid_until,
            recognition_issuer: &self.recognition_issuer,
        };
        canonical_digest_hex(&view)
    }

    /// Pass 2: canonical bytes the credential sub-key signature commits to —
    /// JCS over the view with `recognition_id` present and `signature` removed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        let view = OperatorRecognitionV1NoSig {
            artifact_type: &self.artifact_type,
            system_id: &self.system_id,
            rules_version: &self.rules_version,
            system_root_fingerprint: &self.system_root_fingerprint,
            recognition_id: &self.recognition_id,
            operator_id: &self.operator_id,
            operator_public_key: &self.operator_public_key,
            operator_key_alg: &self.operator_key_alg,
            valid_from: &self.valid_from,
            valid_until: &self.valid_until,
            recognition_issuer: &self.recognition_issuer,
        };
        canonicalize(&view)
    }

    /// Full canonical bytes of the SIGNED credential (includes `signature`).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        canonicalize(self)
    }

    /// Structural validation (does NOT check the signature, or whether the
    /// operator is still recognized — those are separate steps). Enforces the artifact_type, the
    /// recomputed recognition_id, the operator_id matching the public key, the
    /// validity-window ordering, and the canonical-naming guardrail.
    pub fn validate_structure(&self, active_rules_version: &str) -> Result<(), ArtifactError> {
        if self.artifact_type != RECOGNITION_ARTIFACT_TYPE {
            return Err(ArtifactError::InvalidField {
                field: "artifact_type",
                reason: format!(
                    "expected {RECOGNITION_ARTIFACT_TYPE:?}, got {:?}",
                    self.artifact_type
                ),
            });
        }
        if self.rules_version != active_rules_version {
            return Err(ArtifactError::InvalidField {
                field: "rules_version",
                reason: format!(
                    "expected {active_rules_version:?}, got {:?}",
                    self.rules_version
                ),
            });
        }
        if self.operator_key_alg != OPERATOR_KEY_ALG_ACTIVE {
            return Err(ArtifactError::InvalidField {
                field: "operator_key_alg",
                reason: format!("expected {OPERATOR_KEY_ALG_ACTIVE:?}"),
            });
        }
        if self.signature.signature_alg != SIGNATURE_ALG_ACTIVE {
            return Err(ArtifactError::InvalidField {
                field: "signature.signature_alg",
                reason: format!("expected {SIGNATURE_ALG_ACTIVE:?}"),
            });
        }
        if self.valid_from >= self.valid_until {
            return Err(ArtifactError::InvalidField {
                field: "valid_from",
                reason: "valid_from must be strictly before valid_until".into(),
            });
        }
        // operator_id MUST be the one derived from operator_public_key.
        let pk = B64
            .decode(self.operator_public_key.as_bytes())
            .map_err(|e| ArtifactError::InvalidField {
                field: "operator_public_key",
                reason: format!("base64: {e}"),
            })?;
        let expected_id = derive_operator_id(&pk);
        if self.operator_id != expected_id {
            return Err(ArtifactError::InvalidField {
                field: "operator_id",
                reason: "operator_id does not match operator_public_key".into(),
            });
        }
        // recognition_id must be the deterministic digest.
        let recomputed = self.recompute_recognition_id()?;
        if self.recognition_id != recomputed {
            return Err(ArtifactError::InvalidField {
                field: "recognition_id",
                reason: "recognition_id does not match the canonical digest".into(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_inputs(pk_b64: &str) -> RecognitionInputs {
        RecognitionInputs {
            system_root_fingerprint:
                "abababababababababababababababababababababababababababababababab".into(),
            rules_version: "rules/conformance".into(),
            operator_public_key: pk_b64.into(),
            operator_key_alg: OPERATOR_KEY_ALG_ACTIVE.into(),
            valid_from: Utc.with_ymd_and_hms(2026, 6, 15, 12, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2026, 9, 13, 12, 0, 0).unwrap(),
            recognition_issuer: RecognitionIssuer {
                kid: "dev:cred-kid".into(),
                manifest_sequence: 1,
            },
        }
    }

    #[test]
    fn id_two_pass_and_operator_id_derivation() {
        let pk = vec![7u8; 1952]; // dummy pk bytes
        let pk_b64 = B64.encode(&pk);
        let inputs = sample_inputs(&pk_b64);
        let operator_id = derive_operator_id(&pk);
        let id1 =
            OperatorRecognitionCredentialV1::compute_recognition_id(&inputs, &operator_id).unwrap();
        let id2 =
            OperatorRecognitionCredentialV1::compute_recognition_id(&inputs, &operator_id).unwrap();
        assert_eq!(id1, id2, "recognition_id is deterministic");
        assert!(operator_id.starts_with("op:"));
    }
}
