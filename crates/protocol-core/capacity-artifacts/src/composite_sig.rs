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

//! Composite signature wire type (CERTCRYPT Composite Signature Profile, `composite-signature/1`).
//!
//! The canonical serialized form of a composite signature across every artifact
//! (capacity-evidence Level-1, independence-proof, system-foundation root):
//!
//! ```json
//! {
//!   "alg": "certcrypt-composite-p256-mldsa65-v1",
//!   "mode": "AND",
//!   "signatures": [
//!     { "alg": "ECDSA-P256-SHA3-256", "encoding": "raw-rs-64", "low_s": true, "sig_b64": "..." },
//!     { "alg": "ML-DSA-65", "sig_b64": "..." }
//!   ]
//! }
//! ```
//!
//! Detached components (NOT a single ASN.1 blob); ordered classical-first,
//! PQC-second (load-bearing). The verifier in `capacity-verify::composite`
//! consumes this; only `verifyComposite` is a trust verdict (composite-only).

use serde::{Deserialize, Serialize};

/// Composite profile ids.
pub const PROFILE_P256_MLDSA65: &str = "certcrypt-composite-p256-mldsa65-v1";
pub const PROFILE_ED25519_MLDSA65: &str = "certcrypt-composite-ed25519-mldsa65-v1";

/// Component algorithm ids (CERTCRYPT profile names; `ECDSA-P256-SHA3-256`
/// reflects the SHA3 hash domain — NOT a JOSE/COSE standard name).
pub const ALG_ECDSA_P256: &str = "ECDSA-P256-SHA3-256";
pub const ALG_ED25519: &str = "Ed25519";
pub const ALG_MLDSA65: &str = "ML-DSA-65";

/// One detached component signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComponentSignature {
    pub alg: String,
    /// Signature encoding. Present (and `"raw-rs-64"`) for ECDSA; omitted for
    /// ML-DSA/Ed25519 whose encodings are fixed by the alg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Low-s flag for ECDSA (always `true`); omitted for other algs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_s: Option<bool>,
    pub sig_b64: String,
}

impl ComponentSignature {
    pub fn ecdsa_p256(sig_b64: String) -> Self {
        Self {
            alg: ALG_ECDSA_P256.into(),
            encoding: Some("raw-rs-64".into()),
            low_s: Some(true),
            sig_b64,
        }
    }
    pub fn ed25519(sig_b64: String) -> Self {
        Self {
            alg: ALG_ED25519.into(),
            encoding: None,
            low_s: None,
            sig_b64,
        }
    }
    pub fn mldsa65(sig_b64: String) -> Self {
        Self {
            alg: ALG_MLDSA65.into(),
            encoding: None,
            low_s: None,
            sig_b64,
        }
    }
}

/// The composite signature as it appears on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompositeSignatureWire {
    pub alg: String,
    pub mode: String,
    pub signatures: Vec<ComponentSignature>,
}

impl CompositeSignatureWire {
    /// Construct an AND-mode composite under `profile_alg` with the given ordered
    /// components (classical first, PQC second).
    pub fn and(profile_alg: &str, signatures: Vec<ComponentSignature>) -> Self {
        Self {
            alg: profile_alg.into(),
            mode: "AND".into(),
            signatures,
        }
    }

    /// The classical component (P-256 or Ed25519), when it is where the profile
    /// puts it: first.
    pub fn classical(&self) -> Option<&ComponentSignature> {
        self.signatures
            .first()
            .filter(|c| c.alg == ALG_ECDSA_P256 || c.alg == ALG_ED25519)
    }

    /// The ML-DSA-65 (PQC) component, when it is where the profile puts it:
    /// second.
    pub fn mldsa(&self) -> Option<&ComponentSignature> {
        self.signatures.get(1).filter(|c| c.alg == ALG_MLDSA65)
    }
}
