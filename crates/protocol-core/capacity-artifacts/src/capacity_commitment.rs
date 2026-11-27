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

//! System-identity + signature-algorithm anchors for the capacity artifacts.
//!
//! Two protocol-wide constants: the active `system_id` every artifact carries
//! and the active ML-DSA-65 signature-algorithm tag. Consumers resolve them as `capacity_commitment::SYSTEM_ID_ACTIVE` /
//! `SIGNATURE_ALG_ACTIVE`. The holder's signed capacity proof is the projected
//! `capacity.evidence/1` ([`crate::capacity_evidence::ProjectedCommitment`]).

/// The active system identity (`system_id`) every artifact carries.
pub const SYSTEM_ID_ACTIVE: &str = "certcrypt";
/// The active signature algorithm tag (ML-DSA-65, FIPS 204).
pub const SIGNATURE_ALG_ACTIVE: &str = "ml-dsa-65-fips204-v1";
