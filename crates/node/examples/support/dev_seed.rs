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

//! Loading a development key from the environment, for the generator examples.
//!
//! These examples produce material a local deployment needs — a foundation statement, a
//! recognition credential — and to sign it they need the key the deployment
//! already uses. That key is never in this repository: it lives in whatever the
//! operator configured, and this module only reads it.
//!
//! FAILS CLOSED when nothing is configured. Minting a key here instead would
//! produce material signed by something no other process knows, and every
//! artifact verified against it would be rejected later — far from the cause.

#![allow(dead_code)] // Each example uses one of the two loaders.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// Base64 of the 32-byte seed for the system-domain Level-1 key.
pub const ENV_L1_SEED_B64: &str = "CERTCRYPT_DEV_L1_SEED_B64";

/// Base64 of the 32-byte seed for the credential-signing sub-key. A DISTINCT
/// key, so a credential-key compromise does not reach the proof key.
pub const ENV_CRED_SEED_B64: &str = "CERTCRYPT_DEV_CRED_SEED_B64";

/// An ML-DSA-65 keypair loaded from a seed, with the kid it resolves under.
pub struct DevKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub kid: String,
}

/// `dev:` + base64(SHA3-256(public_key)[0..16]), no padding.
///
/// Sixteen bytes, not thirty-two: the kid identifies, it does not authenticate —
/// the signature does that. Every party that resolves the key computes it the
/// same way, so it is defined once, in `capacity_verify::manifest`.
pub fn derive_kid(public_key: &[u8]) -> String {
    capacity_verify::manifest::derive_kid(public_key)
}

/// The system-domain Level-1 key, from the environment.
pub fn load_l1() -> Result<DevKey, String> {
    load_seed(ENV_L1_SEED_B64, "system-domain L1")
}

/// The credential-signing sub-key, from the environment.
pub fn load_credential() -> Result<DevKey, String> {
    load_seed(ENV_CRED_SEED_B64, "credential sub-key")
}

fn load_seed(var: &str, role: &str) -> Result<DevKey, String> {
    let seed_b64 = std::env::var(var)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            format!(
                "{var} is not set, so the {role} cannot be loaded. This example signs with the \
                 key the deployment already uses; it will not mint one, because a self-minted \
                 key produces artifacts nothing else can verify."
            )
        })?;
    let seed = B64
        .decode(seed_b64.trim())
        .map_err(|e| format!("{var} is not valid base64: {e}"))?;
    if seed.len() != 32 {
        return Err(format!(
            "{var} decodes to {} bytes, expected 32 (ML-DSA-65 seed)",
            seed.len()
        ));
    }
    let (public_key, secret_key) =
        capacity_verify::mldsa::keypair_from_seed(&seed).map_err(|e| format!("{var}: {e}"))?;
    let kid = derive_kid(&public_key);
    Ok(DevKey {
        public_key,
        secret_key,
        kid,
    })
}
