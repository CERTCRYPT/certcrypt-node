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

//! Emit a development `system-foundation/1` statement for the node's trust anchor.
//!
//! The node trusts the system-domain Level-1 public key only as published in a
//! signed foundation statement: a bootstrap `system-manifest/1` whose digest is
//! the pinned `system_root_fingerprint`, signed by a quorum of its members, with
//! the Level-1 key covered by those signatures. In production that statement is
//! the one the system domain's key ceremony emits, not this tool's output.
//!
//! For a local test deployment this produces an equivalent statement around
//! YOUR Level-1 key, so bindings minted under that key verify against it. The
//! two root members (2-of-2) are derived deterministically from the same seed,
//! so the same seed always yields the same statement and the same fingerprint.
//! That makes the root exactly as secret as the Level-1 seed — acceptable for
//! development material, never for a real deployment.
//!
//! Usage (from the repository root):
//!   CERTCRYPT_DEV_L1_SEED_B64=<base64 of your 32-byte Level-1 seed> \
//!   cargo run -p certcrypt-node --example gen_dev_foundation > system-foundation.json
//!
//! Optional: `CERTCRYPT_DEV_RULES_VERSIONS` (comma-separated) fills
//! `published_rules_versions`; the node does not read it.
//!
//! The statement goes to stdout; its `system_root_fingerprint` goes to stderr.
//! Pin that fingerprint as `CERTCRYPT_SYSTEM_ROOT_FINGERPRINT` on the node AND on
//! the issuance service that mints the bindings, and point
//! `CERTCRYPT_SYSTEM_FOUNDATION_PATH` at the file. Keep the output out of
//! version control: it describes your deployment, not this repository.

#[path = "support/dev_seed.rs"]
mod dev_seed_mod;
use dev_seed_mod as dev_seed_impl;

use capacity_verify::foundation::{
    sign_foundation_statement, FoundationManifestResolver, FoundationRootMember,
    FoundationStatementInput,
};
use sha3::{Digest, Sha3_256};

/// Domain separation for the root members derived from the Level-1 seed.
const ROOT_MEMBER_DOMAIN: &[u8] = b"certcrypt-node/gen_dev_foundation/root-member/v1";
/// A fixed instant, so the output depends on the seed alone.
const FIXED_TIME: &str = "2026-01-01T00:00:00Z";

fn main() -> Result<(), String> {
    // ML-DSA half + P-256 half of the Level-1 key derived from the SAME 32-byte
    // seed (the canonical composite of `composite-signature/1`).
    let l1 = dev_seed_impl::load_l1().map_err(|e| format!("load L1: {e}"))?;
    let l1_seed: [u8; 32] = l1
        .secret_key
        .as_slice()
        .try_into()
        .map_err(|_| "L1 secret is not a 32-byte seed".to_string())?;
    let l1_p256 = capacity_verify::ecdsa_p256::public_key_sec1(
        &capacity_verify::ecdsa_p256::signing_key_from_seed(&l1_seed),
        false,
    );

    // Two root members, each one composite key from one derived seed.
    let mut roots = Vec::new();
    for i in 0u8..2 {
        let mut h = Sha3_256::new();
        h.update(ROOT_MEMBER_DOMAIN);
        h.update([i]);
        h.update(l1_seed);
        let seed: [u8; 32] = h.finalize().into();
        let (mldsa_pk, mldsa_sk) = capacity_verify::mldsa::keypair_from_seed(&seed)
            .map_err(|e| format!("root member {i}: {e}"))?;
        let p256 = capacity_verify::ecdsa_p256::signing_key_from_seed(&seed);
        roots.push((format!("dev-member-{i}"), p256, mldsa_pk, mldsa_sk));
    }
    let members: Vec<FoundationRootMember<'_>> = roots
        .iter()
        .map(|(kid, p256, pk, sk)| FoundationRootMember {
            member_kid: kid,
            p256_signing_key: p256,
            mldsa_public_key: pk,
            mldsa_secret_key: sk,
        })
        .collect();

    let rules_versions: Vec<String> = std::env::var("CERTCRYPT_DEV_RULES_VERSIONS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();

    let statement = sign_foundation_statement(&FoundationStatementInput {
        foundation_statement_id: "dev-foundation",
        system_id: "certcrypt",
        bootstrap_kid: "dev-root",
        bootstrap_valid_from: FIXED_TIME,
        quorum_k: 2,
        members: &members,
        capacity_key_p256: &l1_p256,
        capacity_key_mldsa: &l1.public_key,
        published_rules_versions: &rules_versions,
        statement_issued_at: FIXED_TIME,
    })
    .map_err(|e| format!("sign statement: {e}"))?;

    // Refuse to emit anything the node itself would not accept.
    let fingerprint = statement["system_root_fingerprint"]
        .as_str()
        .ok_or("statement carries no system_root_fingerprint")?
        .to_owned();
    let bytes = serde_json::to_vec_pretty(&statement).map_err(|e| e.to_string())?;
    let resolver = FoundationManifestResolver::from_statement_bytes(&bytes, &fingerprint, None)
        .map_err(|e| format!("generated statement does not verify: {e}"))?;
    if resolver.level1_kid() != l1.kid {
        return Err("the Level-1 kid does not match the one bindings are minted under".into());
    }

    println!("{}", String::from_utf8(bytes).map_err(|e| e.to_string())?);
    eprintln!("system_root_fingerprint={fingerprint}");
    eprintln!("level1_kid={}", l1.kid);
    Ok(())
}
