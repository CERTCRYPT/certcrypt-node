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

//! Verification errors.
//!
//! `VerifyError` covers the failures this crate raises as typed errors: key or
//! signature material rejected by [`crate::mldsa`], [`crate::ecdsa_p256`] or
//! [`crate::composite`], and a commitment expiring after its authorization. The zero-data
//! capacity-evidence verifier ([`crate::verify_capacity_evidence`]) reports its
//! own outcome as `CapacityVerdict::Unverifiable(String)`, not through this enum.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("expires_at {expires_at} exceeds authorization valid_until {valid_until}")]
    ExpiresAtExceedsAuthorization {
        expires_at: String,
        valid_until: String,
    },

    #[error("ML-DSA-65 key/signature material rejected: {0}")]
    MldsaMaterial(String),

    #[error("ECDSA P-256 key/signature material rejected: {0}")]
    EcdsaMaterial(String),

    #[error("composite hybrid signature material rejected: {0}")]
    CompositeMaterial(String),
}

pub type VerifyResult<T> = Result<T, VerifyError>;
