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

//! Operator receipt — the node signs WHO operated a submission, with its
//! own operator identity, SEPARATELY from the artifact.
//!
//! Two distinct things must never be conflated:
//!
//!   - The certificate / submission set: the operator identity is NOT stamped
//!     per certificate. When a recognized node carried the submission, the proof
//!     names that node in its `node_attestation` (`independence.proof/1` §10.15),
//!     signed by the system domain; a verifier needs no receipt to reach the
//!     `INDEPENDENT` verdict.
//!
//!   - The operator identity: stable, and recognized by the system domain
//!     through an `operator.recognition/1` credential the node presents.
//!
//! So the receipt is a SEPARATE, detachable artifact: the node signs a small
//! envelope binding its `operator_id` to a submission set by the set's `submission_set_id`
//! (an opaque digest), plus the system/rules context and a timestamp. It is
//! auxiliary and detachable; a party that holds it can confirm "operator `<id>`
//! processed this submission set". A verifier WITHOUT it reaches the same verdict.
//!
//! The operator key is the node's OWN identity key — NOT the system-domain L1
//! key (CERTCRYPT's authority-of-definition) and NOT the issuer's holder key
//! (the emission). It records operation/transport, not validity and not emission.

use capacity_verify::mldsa;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Receipt artifact type tag.
pub const OPERATOR_RECEIPT_VERSION: &str = "operator.receipt/1";
/// Signature algorithm (matches the rest of the stack).
pub const OPERATOR_SIG_ALG: &str = "ml-dsa-65-fips204-v1";

/// The node's operator identity: an ML-DSA-65 keypair plus a deterministic
/// `operator_id` derived from the public key. The same id is the subject of the
/// node's `operator.recognition/1` credential and the `node_id` a proof's
/// `node_attestation` carries.
pub struct OperatorIdentity {
    pub operator_id: String,
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl OperatorIdentity {
    /// Build an identity from an existing ML-DSA-65 keypair (e.g. loaded from a
    /// persisted operator key). The `operator_id` is derived from the public key
    /// so it is stable and verifiable by anyone holding the public key.
    pub fn from_keypair(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        let operator_id = derive_operator_id(&public_key);
        Self {
            operator_id,
            public_key,
            secret_key,
        }
    }

    /// Generate a fresh operator identity (dev / first run). In production the
    /// operator key is provisioned once and persisted, not minted per process.
    pub fn generate() -> Self {
        let (public_key, secret_key) = mldsa::keypair();
        Self::from_keypair(public_key, secret_key)
    }

    /// The operator secret key bytes. Exposed so a freshly-generated identity can
    /// be PERSISTED (a real operator key is provisioned once and reloaded across
    /// restarts via `from_keypair`, so `operator_id` stays stable). Handle as a
    /// secret — do not log or ship it.
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    /// Prove possession of the operator secret key by signing `challenge`: the
    /// possession proof that accompanies the recognition credential on a
    /// submission (`<request_id>.<submission_set_id>`) and on an issuer read
    /// (`certcrypt:read:2|<challenge>|<resource>`); it defeats credential
    /// sharing/theft, since the credential bytes are useless without the key. The
    /// caller builds the message. A domain-binding statement needs no separate
    /// proof: its own signature is the possession proof.
    /// Returns the base64 (standard) ML-DSA-65 signature over `challenge`.
    pub fn sign_challenge(&self, challenge: &[u8]) -> Result<String, String> {
        let sig = mldsa::sign_detached(&self.secret_key, challenge)
            .map_err(|e| format!("challenge sign: {e}"))?;
        use base64::Engine as _;
        Ok(base64::engine::general_purpose::STANDARD.encode(&sig))
    }

    /// Verify a possession-proof signature over `challenge` against an operator
    /// public key. Fail-closed.
    pub fn verify_challenge(
        operator_public_key: &[u8],
        challenge: &[u8],
        signature_b64: &str,
    ) -> Result<(), String> {
        use base64::Engine as _;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(signature_b64.as_bytes())
            .map_err(|e| format!("challenge signature base64: {e}"))?;
        mldsa::verify_detached(operator_public_key, &sig, challenge)
            .map_err(|e| format!("challenge verify: {e}"))
    }

    /// Sign an receipt that this operator processed the submission set identified by
    /// `submission_set_id`, under the given system/rules context, at `issued_at`
    /// (RFC 3339; the caller supplies it — no hidden clock read here).
    pub fn issue_receipt(
        &self,
        submission_set_id: &str,
        system_id: &str,
        rules_version: &str,
        issued_at: &str,
    ) -> Result<OperatorReceipt, String> {
        let view = OperatorReceiptNoSig {
            receipt_version: OPERATOR_RECEIPT_VERSION,
            operator_id: &self.operator_id,
            submission_set_id,
            system_id,
            rules_version,
            issued_at,
        };
        let signing_bytes =
            serde_jcs::to_vec(&view).map_err(|e| format!("receipt canonicalize: {e}"))?;
        let sig = mldsa::sign_detached(&self.secret_key, &signing_bytes)
            .map_err(|e| format!("receipt sign: {e}"))?;
        use base64::Engine as _;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);
        Ok(OperatorReceipt {
            receipt_version: OPERATOR_RECEIPT_VERSION.to_string(),
            operator_id: self.operator_id.clone(),
            submission_set_id: submission_set_id.to_string(),
            system_id: system_id.to_string(),
            rules_version: rules_version.to_string(),
            issued_at: issued_at.to_string(),
            signature: OperatorSignature {
                signature_alg: OPERATOR_SIG_ALG.to_string(),
                signature_b64,
            },
        })
    }
}

/// Deterministic operator id from the public key: `op:` + base64(no-pad) of the
/// first 16 bytes of SHA3-256(public_key). Stable, public, and verifiable by
/// anyone holding the public key. (Same derivation discipline as the dev L1 kid.)
pub fn derive_operator_id(public_key: &[u8]) -> String {
    use base64::Engine as _;
    let digest = Sha3_256::digest(public_key);
    let truncated = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&digest[..16]);
    format!("op:{truncated}")
}

/// The no-signature view that the operator signature commits to (JCS-canonical;
/// serde_jcs sorts keys, so field order here is informational only).
#[derive(Serialize)]
struct OperatorReceiptNoSig<'a> {
    receipt_version: &'a str,
    operator_id: &'a str,
    submission_set_id: &'a str,
    system_id: &'a str,
    rules_version: &'a str,
    issued_at: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorSignature {
    pub signature_alg: String,
    pub signature_b64: String,
}

/// The detachable, opt-in operator receipt. Binds an `operator_id` to a
/// `submission_set_id` (opaque digest) — NOT to the submission set's linkable content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorReceipt {
    pub receipt_version: String,
    pub operator_id: String,
    pub submission_set_id: String,
    pub system_id: String,
    pub rules_version: String,
    pub issued_at: String,
    pub signature: OperatorSignature,
}

impl OperatorReceipt {
    /// Re-derive the signing bytes (no-sig JCS view) for verification.
    fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let view = OperatorReceiptNoSig {
            receipt_version: &self.receipt_version,
            operator_id: &self.operator_id,
            submission_set_id: &self.submission_set_id,
            system_id: &self.system_id,
            rules_version: &self.rules_version,
            issued_at: &self.issued_at,
        };
        serde_jcs::to_vec(&view).map_err(|e| format!("receipt canonicalize: {e}"))
    }

    /// Verify the receipt signature against an operator public key — the key
    /// the operator's `operator.recognition/1` credential carries for this
    /// `operator_id`. Fail-closed: any mismatch is an error. This only proves the
    /// bytes were signed by the holder of `operator_public_key`; whether that key
    /// is recognized is a separate check on the credential.
    pub fn verify_signature(&self, operator_public_key: &[u8]) -> Result<(), String> {
        if self.signature.signature_alg != OPERATOR_SIG_ALG {
            return Err(format!(
                "unexpected operator signature_alg: {}",
                self.signature.signature_alg
            ));
        }
        // The operator_id MUST be the one derived from the key we verify against,
        // or an attacker could present someone else's signature under a swapped id.
        let expected_id = derive_operator_id(operator_public_key);
        if self.operator_id != expected_id {
            return Err(format!(
                "operator_id {} does not match the public key (derives {})",
                self.operator_id, expected_id
            ));
        }
        use base64::Engine as _;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(self.signature.signature_b64.as_bytes())
            .map_err(|e| format!("operator signature base64: {e}"))?;
        let bytes = self.signing_bytes()?;
        mldsa::verify_detached(operator_public_key, &sig, &bytes)
            .map_err(|e| format!("operator signature verify: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_round_trip() {
        let op = OperatorIdentity::generate();
        let att = op
            .issue_receipt(
                "5d359cc576b65a27af4be302fae16cbc2802211e20818e23c7bc145af2e19744",
                "certcrypt",
                "rules/conformance",
                "2026-06-16T12:00:00Z",
            )
            .unwrap();
        // Verifies against the operator's own public key.
        att.verify_signature(&op.public_key).unwrap();
        assert!(att.operator_id.starts_with("op:"));
    }

    #[test]
    fn wrong_key_fails_closed() {
        let op = OperatorIdentity::generate();
        let other = OperatorIdentity::generate();
        let att = op
            .issue_receipt(
                "aa",
                "certcrypt",
                "rules/conformance",
                "2026-06-16T12:00:00Z",
            )
            .unwrap();
        // A different operator's key must not verify (and id won't match either).
        assert!(att.verify_signature(&other.public_key).is_err());
    }

    #[test]
    fn tampered_submission_set_id_fails() {
        let op = OperatorIdentity::generate();
        let mut att = op
            .issue_receipt(
                "aa",
                "certcrypt",
                "rules/conformance",
                "2026-06-16T12:00:00Z",
            )
            .unwrap();
        att.submission_set_id = "bb".into();
        assert!(att.verify_signature(&op.public_key).is_err());
    }

    #[test]
    fn operator_id_is_deterministic() {
        let (pk, _sk) = mldsa::keypair();
        assert_eq!(derive_operator_id(&pk), derive_operator_id(&pk));
    }
}
