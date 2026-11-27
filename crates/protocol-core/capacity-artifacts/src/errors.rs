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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("JSON serialization failed: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("JCS canonicalization failed: {0}")]
    Jcs(String),

    #[error("invalid field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },

    #[error("commitment_id mismatch: declared={declared}, recomputed={recomputed}")]
    CommitmentIdMismatch {
        declared: String,
        recomputed: String,
    },

    #[error("authorization_id mismatch: declared={declared}, recomputed={recomputed}")]
    AuthorizationIdMismatch {
        declared: String,
        recomputed: String,
    },
}
