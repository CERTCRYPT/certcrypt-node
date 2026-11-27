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

//! ML-DSA-65 (FIPS 204) signing and verification helpers.
//!
//! Backed by `ml-dsa` (RustCrypto). Seed-based, like the JS SDK/verifier (noble)
//! and the conformance goldens (dilithium-py): the same seed yields the same
//! public key (1952 B) in all three, and their signatures (3309 B) cross-verify.
//!
//! Key model: the secret key is the **32-byte FIPS 204 seed** (Algorithm 6). A
//! keypair is regenerated from it deterministically on demand; the expanded
//! private key is never persisted.

use crate::errors::VerifyError;
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey, B32,
};

pub const ALG_ID: &str = "ml-dsa-65-fips204-v1";

/// The compact secret-key form we persist and pass around: the 32-byte seed.
pub const SEED_LEN: usize = 32;

pub fn public_key_bytes_len() -> usize {
    // ML-DSA-65 verifying key: 1952 bytes.
    1952
}

pub fn signature_bytes_len() -> usize {
    // ML-DSA-65 detached signature: 3309 bytes.
    3309
}

/// Generate a fresh keypair. Returns `(public_key_bytes, secret_key_bytes)` where
/// the secret key is the 32-byte seed. Deterministic given the seed.
pub fn keypair() -> (Vec<u8>, Vec<u8>) {
    // Fresh 32-byte seed from the OS CSPRNG, then derive.
    let mut seed_bytes = [0u8; SEED_LEN];
    getrandom_seed(&mut seed_bytes);
    let (pk, _) = keypair_from_seed_bytes(&seed_bytes).expect("fresh seed is valid");
    (pk, seed_bytes.to_vec())
}

/// Derive a keypair from a 32-byte seed (FIPS 204 Algorithm 6). Returns
/// `(public_key_bytes, seed_bytes)`. The public key matches what any FIPS 204
/// implementation (noble, dilithium-py) derives from the same seed.
pub fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VerifyError> {
    let (pk, _sk) = keypair_from_seed_bytes(seed)?;
    Ok((pk, seed.to_vec()))
}

fn keypair_from_seed_bytes(seed: &[u8]) -> Result<(Vec<u8>, SigningKey<MlDsa65>), VerifyError> {
    let seed_arr = B32::try_from(seed).map_err(|_| {
        VerifyError::MldsaMaterial(format!("seed must be {SEED_LEN} bytes, got {}", seed.len()))
    })?;
    let sk = SigningKey::<MlDsa65>::from_seed(&seed_arr);
    let pk = sk.verifying_key().encode().to_vec();
    Ok((pk, sk))
}

/// Sign `message` with the secret key (a 32-byte seed). Deterministic ML-DSA-65
/// detached signature, empty context — byte-identical to PQClean `detached_sign`.
pub fn sign_detached(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let (_pk, sk) = keypair_from_seed_bytes(secret_key)?;
    let sig: Signature<MlDsa65> = sk.sign(message);
    Ok(sig.encode().to_vec())
}

pub fn verify_detached(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), VerifyError> {
    let enc_pk = EncodedVerifyingKey::<MlDsa65>::try_from(public_key).map_err(|_| {
        VerifyError::MldsaMaterial(format!("invalid public key length: {}", public_key.len()))
    })?;
    let vk = VerifyingKey::<MlDsa65>::decode(&enc_pk);
    let enc_sig = EncodedSignature::<MlDsa65>::try_from(signature).map_err(|_| {
        VerifyError::MldsaMaterial(format!("invalid signature length: {}", signature.len()))
    })?;
    let sig = Signature::<MlDsa65>::decode(&enc_sig)
        .ok_or_else(|| VerifyError::MldsaMaterial("signature decode failed".to_string()))?;
    vk.verify(message, &sig)
        .map_err(|e| VerifyError::MldsaMaterial(format!("signature verification failed: {e}")))
}

fn getrandom_seed(out: &mut [u8; SEED_LEN]) {
    // Minimal OS CSPRNG fill without pulling rand: use getrandom via std.
    // `ml-dsa`'s Generate would also work, but we keep the seed explicit so the
    // returned secret key IS the seed.
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    f.read_exact(out).expect("read /dev/urandom");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_round_trip() {
        let (pk, sk) = keypair();
        assert_eq!(sk.len(), SEED_LEN);
        assert_eq!(pk.len(), public_key_bytes_len());
        let msg = b"hello capacity world";
        let sig = sign_detached(&sk, msg).unwrap();
        assert_eq!(sig.len(), signature_bytes_len());
        verify_detached(&pk, &sig, msg).unwrap();
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [7u8; SEED_LEN];
        let (pk1, _) = keypair_from_seed(&seed).unwrap();
        let (pk2, _) = keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1, pk2, "same seed → same public key");
        // and the signature is deterministic too
        let s1 = sign_detached(&seed, b"m").unwrap();
        let s2 = sign_detached(&seed, b"m").unwrap();
        assert_eq!(s1, s2, "deterministic signature");
    }

    #[test]
    fn tampered_message_fails_verification() {
        let (pk, sk) = keypair();
        let msg = b"hello capacity world";
        let sig = sign_detached(&sk, msg).unwrap();
        let mut other = msg.to_vec();
        other[0] ^= 0x01;
        assert!(verify_detached(&pk, &sig, &other).is_err());
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let (pk, sk) = keypair();
        let msg = b"hello";
        let mut sig = sign_detached(&sk, msg).unwrap();
        sig[0] ^= 0x01;
        assert!(verify_detached(&pk, &sig, msg).is_err());
    }
}
