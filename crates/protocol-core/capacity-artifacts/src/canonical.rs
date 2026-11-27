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

//! JCS canonicalization (RFC 8785) and SHA3-256 digesting helpers.
//!
//! Deterministic identifiers and digests — the capacity evidence digest
//! (`capacity.evidence/1` §7), `proof_id` and `proof_digest`
//! (`independence.proof/1`) — are computed over JCS-canonical bytes, some of them
//! over a view with the identifier or signature members removed. This module
//! provides the primitives.

use crate::errors::ArtifactError;
use serde::Serialize;
use sha3::{Digest, Sha3_256};

/// Canonicalize a serializable value into RFC 8785 JCS UTF-8 bytes.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, ArtifactError> {
    serde_jcs::to_vec(value).map_err(ArtifactError::from)
}

/// SHA3-256 digest of the canonical bytes, returned as 64-character lowercase hex.
pub fn sha3_256_hex(bytes: &[u8]) -> String {
    let mut h = Sha3_256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Canonicalize and digest in one pass. The caller is responsible for stripping
/// signature/identifier members from the value before invoking this helper when
/// the digest is meant to be the deterministic identifier of the artifact.
pub fn canonical_digest_hex<T: Serialize>(value: &T) -> Result<String, ArtifactError> {
    let bytes = canonicalize(value)?;
    Ok(sha3_256_hex(&bytes))
}

/// 64-character lowercase hex string check.
pub fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
