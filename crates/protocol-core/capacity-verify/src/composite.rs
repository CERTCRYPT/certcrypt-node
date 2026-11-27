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

//! Composite signature (CERTCRYPT Composite Signature Profile), `composite-signature/1`.
//!
//! The permanent trust chain (the Proof of Independence, the Level-1
//! authorization binding, the emission certificate, the system-foundation root)
//! signs as a **composite**: every component signs the SAME domain-separated
//! message `M'`, and verification is **AND** — valid iff ALL components verify.
//! Binding the composite alg id into `M'` stops a component signature being
//! lifted out and replayed under another profile (anti-stripping, anti
//! cross-profile).
//!
//!   M' = ASCII(domain_prefix) || 0x00 || ASCII(composite_alg_id) || 0x00
//!        || ASCII(payload_canon_digest_hex)
//!
//! `domain_prefix = "CERTCRYPT-Composite-Signature-v1"` (no year). The `0x00`
//! separators make the field split injective (no ASCII field contains 0x00), so
//! two distinct triples can never collide on the same `M'`.
//!
//! Canonical profile `certcrypt-composite-p256-mldsa65-v1`: components are
//! ECDSA-P256-SHA3-256 (classical, first) + ML-DSA-65 (post-quantum). The
//! additional profile `certcrypt-composite-ed25519-mldsa65-v1` swaps the
//! classical component for Ed25519. Component order is load-bearing.
//!
//! Rust mirror of `verifier-toolkit-js/core/crypto/composite.ts` and the
//! conformance generator. `M'` bytes are load-bearing cross-language; signature
//! BYTES can differ between implementations (ML-DSA signing may be hedged), but a
//! Rust-produced composite verifies under the JS verifier because they agree on
//! `M'`. Fail-closed: the PQC (ML-DSA) component can never be skipped.

use crate::ecdsa_p256;
use crate::errors::{VerifyError, VerifyResult};
use crate::mldsa;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use capacity_artifacts::composite_sig::{
    ComponentSignature, CompositeSignatureWire, ALG_ECDSA_P256, ALG_ED25519, ALG_MLDSA65,
    PROFILE_ED25519_MLDSA65, PROFILE_P256_MLDSA65,
};
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};

/// The composite profile under which the system domain's signatures are verified
/// (`rules/2026-01` Section 17). Callers pass this as the expected profile rather
/// than the one a signature declares: a signature under any other profile fails,
/// even where it would verify under that profile.
pub const REQUIRED_PROFILE: &str = PROFILE_P256_MLDSA65;
use sha3::{Digest, Sha3_256};

/// Fixed domain-separation prefix (no year — version lives in the profile id).
pub const COMPOSITE_DOMAIN_PREFIX: &[u8] = b"CERTCRYPT-Composite-Signature-v1";
const SEP: u8 = 0x00;

/// Build the domain-separated message every component signs.
///
/// `payload_canon_digest_hex` is the lowercase-hex `SHA3-256(JCS(payload))`.
/// `composite_alg_id` is the PROFILE id (e.g. [`PROFILE_P256_MLDSA65`]) — bound
/// in so a signature under one profile cannot be reinterpreted under another.
pub fn composite_m_prime(composite_alg_id: &str, payload_canon_digest_hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        COMPOSITE_DOMAIN_PREFIX.len() + 2 + composite_alg_id.len() + payload_canon_digest_hex.len(),
    );
    out.extend_from_slice(COMPOSITE_DOMAIN_PREFIX);
    out.push(SEP);
    out.extend_from_slice(composite_alg_id.as_bytes());
    out.push(SEP);
    out.extend_from_slice(payload_canon_digest_hex.as_bytes());
    out
}

/// Composite KEY fingerprint (`composite-signature/1` §10):
/// `SHA3-256(classical_pub || mldsa_pub)` over the decoded key bytes, classical
/// first (matching component order), PQC second. It identifies one composite
/// key, such as an issuer key. It is not the `system_root_fingerprint` of a
/// system domain, which is the digest of the whole bootstrap manifest
/// (`system-foundation/1` §8). Mirror of the generator's function of the same
/// name.
pub fn composite_root_fingerprint(classical_pub: &[u8], mldsa_pub: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(classical_pub);
    hasher.update(mldsa_pub);
    hex::encode(hasher.finalize())
}

/// Derive the Ed25519 public key (raw 32 bytes) from a 32-byte seed.
pub fn ed25519_public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign `payload_canon_digest_hex` under the canonical P-256+ML-DSA-65 profile.
/// `ecdsa_sk` is a P-256 signing key; `mldsa_secret_key` the PQClean secret.
pub fn composite_sign_p256(
    payload_canon_digest_hex: &str,
    ecdsa_sk: &p256::ecdsa::SigningKey,
    mldsa_secret_key: &[u8],
) -> VerifyResult<CompositeSignatureWire> {
    let m_prime = composite_m_prime(PROFILE_P256_MLDSA65, payload_canon_digest_hex);
    let sig_ecdsa = ecdsa_p256::sign_raw_rs_64(ecdsa_sk, &m_prime);
    let sig_mldsa = mldsa::sign_detached(mldsa_secret_key, &m_prime)?;
    Ok(CompositeSignatureWire::and(
        PROFILE_P256_MLDSA65,
        vec![
            ComponentSignature::ecdsa_p256(B64.encode(sig_ecdsa)),
            ComponentSignature::mldsa65(B64.encode(&sig_mldsa)),
        ],
    ))
}

/// Sign under the additional Ed25519+ML-DSA-65 profile.
pub fn composite_sign_ed25519(
    payload_canon_digest_hex: &str,
    ed25519_secret_seed: &[u8; 32],
    mldsa_secret_key: &[u8],
) -> VerifyResult<CompositeSignatureWire> {
    let m_prime = composite_m_prime(PROFILE_ED25519_MLDSA65, payload_canon_digest_hex);
    let sig_ed25519 = SigningKey::from_bytes(ed25519_secret_seed).sign(&m_prime);
    let sig_mldsa = mldsa::sign_detached(mldsa_secret_key, &m_prime)?;
    Ok(CompositeSignatureWire::and(
        PROFILE_ED25519_MLDSA65,
        vec![
            ComponentSignature::ed25519(B64.encode(sig_ed25519.to_bytes())),
            ComponentSignature::mldsa65(B64.encode(&sig_mldsa)),
        ],
    ))
}

/// Public-key material for composite verification: the classical component's
/// public key and the ML-DSA public key, each in the one encoding its profile
/// fixes (see [`composite_layout`]).
pub struct CompositePublicKeys<'a> {
    pub classical_pub: &'a [u8],
    pub mldsa_pub: &'a [u8],
}

/// FIPS 204 ML-DSA-65 public-key length.
pub const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;
/// SEC1 uncompressed P-256 point length (`0x04 || X || Y`).
pub const P256_SEC1_UNCOMPRESSED_LEN: usize = 65;
/// RFC 8032 Ed25519 public-key length.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Why `sig` and `keys` are not exactly the layout and key encodings of the
/// profile `composite_alg_id` (`composite-signature/1` §6 step 3, §8, §9), or
/// `Ok` when they are: exactly the profile's two components in order, the ECDSA
/// one with `encoding = "raw-rs-64"` and `low_s = true` and the others with
/// neither, and each key in its one encoding — P-256 as a 65-byte SEC1
/// uncompressed point, Ed25519 as its raw 32 bytes, ML-DSA-65 as 1952 bytes.
/// Unknown component members are already refused when the wire is parsed.
pub fn composite_layout(
    composite_alg_id: &str,
    sig: &CompositeSignatureWire,
    keys: &CompositePublicKeys<'_>,
) -> VerifyResult<()> {
    let malformed = |m: String| Err(VerifyError::CompositeMaterial(m));
    let classical_alg = match composite_alg_id {
        a if a == PROFILE_P256_MLDSA65 => ALG_ECDSA_P256,
        a if a == PROFILE_ED25519_MLDSA65 => ALG_ED25519,
        other => return malformed(format!("unsupported composite profile: {other}")),
    };
    if sig.alg != composite_alg_id {
        return malformed(format!(
            "profile mismatch: signature alg {} != expected {composite_alg_id}",
            sig.alg
        ));
    }
    if sig.mode != "AND" {
        return malformed(format!("unsupported composite mode: {}", sig.mode));
    }
    let [classical, pqc] = sig.signatures.as_slice() else {
        return malformed(format!(
            "signatures must hold exactly the 2 components of the profile, got {}",
            sig.signatures.len()
        ));
    };
    if classical.alg != classical_alg {
        return malformed(format!(
            "component 0 must be {classical_alg} (the profile fixes the order), got {}",
            classical.alg
        ));
    }
    if pqc.alg != ALG_MLDSA65 {
        return malformed(format!(
            "component 1 must be {ALG_MLDSA65} (the profile fixes the order), got {}",
            pqc.alg
        ));
    }
    if classical_alg == ALG_ECDSA_P256 {
        if classical.encoding.as_deref() != Some("raw-rs-64") {
            return malformed("ECDSA component encoding must be \"raw-rs-64\"".into());
        }
        if classical.low_s != Some(true) {
            return malformed("ECDSA component low_s must be true".into());
        }
    } else if classical.encoding.is_some() || classical.low_s.is_some() {
        return malformed("Ed25519 component carries only alg and sig_b64".into());
    }
    if pqc.encoding.is_some() || pqc.low_s.is_some() {
        return malformed("ML-DSA-65 component carries only alg and sig_b64".into());
    }
    if classical_alg == ALG_ECDSA_P256 {
        if keys.classical_pub.len() != P256_SEC1_UNCOMPRESSED_LEN || keys.classical_pub[0] != 0x04 {
            return malformed(
                "classical public key must be a SEC1 uncompressed P-256 point (65 bytes, 0x04)"
                    .into(),
            );
        }
    } else if keys.classical_pub.len() != ED25519_PUBLIC_KEY_LEN {
        return malformed("classical public key must be a raw Ed25519 key (32 bytes)".into());
    }
    if keys.mldsa_pub.len() != MLDSA65_PUBLIC_KEY_LEN {
        return malformed(format!(
            "ML-DSA-65 public key must be {MLDSA65_PUBLIC_KEY_LEN} bytes, got {}",
            keys.mldsa_pub.len()
        ));
    }
    Ok(())
}

/// Verify a composite signature over `payload_canon_digest_hex` under
/// `composite_alg_id` — the profile the CONTEXT requires, never the one the
/// signature declares. The layout and key encodings must be exactly the
/// profile's ([`composite_layout`]); then AND, fail-closed on the PQC component.
pub fn verify_composite(
    composite_alg_id: &str,
    payload_canon_digest_hex: &str,
    sig: &CompositeSignatureWire,
    keys: CompositePublicKeys<'_>,
) -> VerifyResult<()> {
    composite_layout(composite_alg_id, sig, &keys)?;
    let m_prime = composite_m_prime(composite_alg_id, payload_canon_digest_hex);
    let (classical, mldsa_comp) = (&sig.signatures[0], &sig.signatures[1]);

    if classical.alg == ALG_ECDSA_P256 {
        let sig_bytes = B64
            .decode(&classical.sig_b64)
            .map_err(|e| VerifyError::CompositeMaterial(format!("ECDSA sig base64: {e}")))?;
        ecdsa_p256::verify_raw_rs_64(keys.classical_pub, &m_prime, &sig_bytes)
            .map_err(|e| VerifyError::CompositeMaterial(format!("ECDSA-P256 component: {e}")))?;
    } else {
        let ed_pub: [u8; 32] = keys.classical_pub.try_into().map_err(|_| {
            VerifyError::CompositeMaterial("Ed25519 pubkey must be 32 bytes".into())
        })?;
        let vk = VerifyingKey::from_bytes(&ed_pub)
            .map_err(|e| VerifyError::CompositeMaterial(format!("Ed25519 pubkey: {e}")))?;
        let sig_ed = B64
            .decode(&classical.sig_b64)
            .map_err(|e| VerifyError::CompositeMaterial(format!("Ed25519 sig base64: {e}")))?;
        let sig_ed: [u8; 64] = sig_ed
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::CompositeMaterial("Ed25519 sig must be 64 bytes".into()))?;
        vk.verify(&m_prime, &EdSignature::from_bytes(&sig_ed))
            .map_err(|e| VerifyError::CompositeMaterial(format!("Ed25519 component: {e}")))?;
    }

    let sig_mldsa = B64
        .decode(&mldsa_comp.sig_b64)
        .map_err(|e| VerifyError::CompositeMaterial(format!("ML-DSA sig base64: {e}")))?;
    mldsa::verify_detached(keys.mldsa_pub, &sig_mldsa, &m_prime)
        .map_err(|e| VerifyError::CompositeMaterial(format!("ML-DSA component: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p256_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap()
    }

    #[test]
    fn m_prime_layout_has_separators_and_alg_id() {
        let digest = "ab".repeat(32);
        let m = composite_m_prime(PROFILE_P256_MLDSA65, &digest);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"CERTCRYPT-Composite-Signature-v1");
        expected.push(0x00);
        expected.extend_from_slice(PROFILE_P256_MLDSA65.as_bytes());
        expected.push(0x00);
        expected.extend_from_slice(digest.as_bytes());
        assert_eq!(m, expected);
    }

    #[test]
    fn p256_sign_verify_round_trip() {
        let (mldsa_pub, mldsa_sk) = mldsa::keypair();
        let ecdsa_sk = p256_key();
        let ecdsa_pub = ecdsa_p256::public_key_sec1(&ecdsa_sk, false);
        let digest = "cd".repeat(32);
        let sig = composite_sign_p256(&digest, &ecdsa_sk, &mldsa_sk).unwrap();
        verify_composite(
            PROFILE_P256_MLDSA65,
            &digest,
            &sig,
            CompositePublicKeys {
                classical_pub: &ecdsa_pub,
                mldsa_pub: &mldsa_pub,
            },
        )
        .expect("p256 composite verifies");
    }

    #[test]
    fn ed25519_profile_round_trip() {
        let (mldsa_pub, mldsa_sk) = mldsa::keypair();
        let seed = [7u8; 32];
        let ed_pub = ed25519_public_from_seed(&seed);
        let digest = "ef".repeat(32);
        let sig = composite_sign_ed25519(&digest, &seed, &mldsa_sk).unwrap();
        verify_composite(
            PROFILE_ED25519_MLDSA65,
            &digest,
            &sig,
            CompositePublicKeys {
                classical_pub: &ed_pub,
                mldsa_pub: &mldsa_pub,
            },
        )
        .expect("ed25519 composite verifies");
    }

    #[test]
    fn wrong_profile_id_fails_anti_cross_profile() {
        let (mldsa_pub, mldsa_sk) = mldsa::keypair();
        let ecdsa_sk = p256_key();
        let ecdsa_pub = ecdsa_p256::public_key_sec1(&ecdsa_sk, false);
        let digest = "12".repeat(32);
        let sig = composite_sign_p256(&digest, &ecdsa_sk, &mldsa_sk).unwrap();
        // Verifying under a different profile id changes M' → must fail.
        assert!(verify_composite(
            PROFILE_ED25519_MLDSA65,
            &digest,
            &sig,
            CompositePublicKeys {
                classical_pub: &ecdsa_pub,
                mldsa_pub: &mldsa_pub
            },
        )
        .is_err());
    }

    #[test]
    fn corrupt_mldsa_fails_and_semantics() {
        let (mldsa_pub, mldsa_sk) = mldsa::keypair();
        let ecdsa_sk = p256_key();
        let ecdsa_pub = ecdsa_p256::public_key_sec1(&ecdsa_sk, false);
        let digest = "34".repeat(32);
        let mut sig = composite_sign_p256(&digest, &ecdsa_sk, &mldsa_sk).unwrap();
        // Corrupt ML-DSA component → AND fails even though ECDSA is valid.
        let mut raw = B64.decode(&sig.signatures[1].sig_b64).unwrap();
        raw[0] ^= 0xFF;
        sig.signatures[1].sig_b64 = B64.encode(&raw);
        assert!(verify_composite(
            PROFILE_P256_MLDSA65,
            &digest,
            &sig,
            CompositePublicKeys {
                classical_pub: &ecdsa_pub,
                mldsa_pub: &mldsa_pub
            },
        )
        .is_err());
    }

    #[test]
    fn missing_pqc_component_fails_closed() {
        let (mldsa_pub, mldsa_sk) = mldsa::keypair();
        let ecdsa_sk = p256_key();
        let ecdsa_pub = ecdsa_p256::public_key_sec1(&ecdsa_sk, false);
        let digest = "56".repeat(32);
        let mut sig = composite_sign_p256(&digest, &ecdsa_sk, &mldsa_sk).unwrap();
        // Strip the ML-DSA component → fail-closed (no PQC floor).
        sig.signatures.retain(|c| c.alg != ALG_MLDSA65);
        assert!(verify_composite(
            PROFILE_P256_MLDSA65,
            &digest,
            &sig,
            CompositePublicKeys {
                classical_pub: &ecdsa_pub,
                mldsa_pub: &mldsa_pub
            },
        )
        .is_err());
    }

    /// A valid P-256 composite with its keys, for the layout refusals below.
    fn signed() -> (CompositeSignatureWire, Vec<u8>, Vec<u8>, String) {
        let (mldsa_pub, mldsa_sk) = mldsa::keypair();
        let ecdsa_sk = p256_key();
        let ecdsa_pub = ecdsa_p256::public_key_sec1(&ecdsa_sk, false);
        let digest = "5a".repeat(32);
        let sig = composite_sign_p256(&digest, &ecdsa_sk, &mldsa_sk).unwrap();
        (sig, ecdsa_pub, mldsa_pub, digest)
    }

    fn refused(sig: &CompositeSignatureWire, classical: &[u8], mldsa_pub: &[u8], digest: &str) {
        let keys = CompositePublicKeys {
            classical_pub: classical,
            mldsa_pub,
        };
        let err = verify_composite(PROFILE_P256_MLDSA65, digest, sig, keys).unwrap_err();
        assert!(matches!(err, VerifyError::CompositeMaterial(_)), "{err}");
    }

    #[test]
    fn layout_refusals_even_when_every_component_verifies() {
        let (sig, ecdsa_pub, mldsa_pub, digest) = signed();
        verify_composite(
            PROFILE_P256_MLDSA65,
            &digest,
            &sig,
            CompositePublicKeys {
                classical_pub: &ecdsa_pub,
                mldsa_pub: &mldsa_pub,
            },
        )
        .expect("the unmodified composite verifies");

        let mut reordered = sig.clone();
        reordered.signatures.reverse();
        refused(&reordered, &ecdsa_pub, &mldsa_pub, &digest);

        let mut extra = sig.clone();
        extra.signatures.push(sig.signatures[1].clone());
        refused(&extra, &ecdsa_pub, &mldsa_pub, &digest);

        let mut der = sig.clone();
        der.signatures[0].encoding = Some("der".into());
        refused(&der, &ecdsa_pub, &mldsa_pub, &digest);

        let mut high = sig.clone();
        high.signatures[0].low_s = Some(false);
        refused(&high, &ecdsa_pub, &mldsa_pub, &digest);

        let mut absent = sig.clone();
        absent.signatures[0].low_s = None;
        refused(&absent, &ecdsa_pub, &mldsa_pub, &digest);
    }

    #[test]
    fn one_encoding_per_key() {
        let (sig, ecdsa_pub, mldsa_pub, digest) = signed();
        // The same point compressed to 33 bytes: same key, other bytes.
        let mut compressed = vec![if ecdsa_pub[64] & 1 == 1 { 0x03 } else { 0x02 }];
        compressed.extend_from_slice(&ecdsa_pub[1..33]);
        refused(&sig, &compressed, &mldsa_pub, &digest);
        // A raw 32-byte key, the Ed25519 encoding, under the P-256 profile.
        refused(&sig, &ecdsa_pub[1..33], &mldsa_pub, &digest);
        // An ML-DSA key one byte short.
        refused(&sig, &ecdsa_pub, &mldsa_pub[..mldsa_pub.len() - 1], &digest);
    }

    #[test]
    fn an_unknown_component_member_does_not_parse() {
        let v = serde_json::json!({
            "alg": ALG_MLDSA65, "sig_b64": "AA==", "note": "x"
        });
        assert!(serde_json::from_value::<ComponentSignature>(v).is_err());
    }
}
