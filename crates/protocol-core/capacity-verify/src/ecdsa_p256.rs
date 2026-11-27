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

//! ECDSA P-256 (secp256r1) — the classical component of the CERTCRYPT Composite
//! Signature Profile (`certcrypt-composite-p256-mldsa65-v1`).
//!
//! Low-level cryptographic PRIMITIVE: this is NOT a trust-verdict API. A
//! composite signature is valid only through the composite verifier (AND of all
//! components). See `composite-signature/1` — "composite-only".
//!
//! Canonical wire form (`composite-signature/1`):
//! - curve P-256 / secp256r1; ECDSA over **SHA3-256** of the signed message
//!   (CERTCRYPT's stack-wide hash — NOT SHA-2; ECDSA is hash-agnostic and reduces
//!   the 32-byte digest mod n either way);
//! - signature encoding `raw-rs-64`: `r || s`, 64 bytes (32+32), NOT DER;
//! - low-s NORMATIVE: the signer emits low-s; the verifier REJECTS high-s
//!   (it does not normalize). A high-s signature fails closed.
//!
//! Because we hash with SHA3-256 (not SHA-2), both sign and verify go through the
//! PREHASH (we hash, then sign/verify the digest) — the convenience APIs would
//! assume SHA-2. The JS verifier hashes with SHA3-256 identically.
//!
//! The signing nonce is RFC 6979 §3.2 with H = SHA3-256: HMAC-SHA3-256 throughout,
//! not the HMAC-SHA-256 that `p256`'s `sign_prehash` hard-wires for this curve.
//! Both verify everywhere; only this one is byte-identical to the conformance
//! family `ecdsa-p256-deterministic`, so one key over one message has exactly one
//! signature across implementations.
//!
//! This crate signs AND verifies; the JS toolkit only verifies. Both agree on the
//! same `raw-rs-64` bytes — that is the cross-language contract sealed by the
//! conformance golden vectors.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::{Curve, FieldBytesEncoding, PrimeField};
use p256::{EncodedPoint, FieldBytes, NistP256, Scalar, U256};
use sha3::{Digest, Sha3_256};

use crate::errors::{VerifyError, VerifyResult};

/// Sign `message` with ECDSA P-256 over SHA3-256, returning a `raw-rs-64`
/// signature guaranteed low-s.
///
/// Exactly the construction of the conformance family `ecdsa-p256-deterministic`:
/// - prehash `h = SHA3-256(message)`, hashed once;
/// - nonce `k` per RFC 6979 §3.2 with H = SHA3-256 (HMAC-SHA3-256 throughout),
///   `x` = the private scalar as 32 big-endian bytes, `bits2octets(h) =
///   int(h) mod n` as 32 bytes, no additional data;
/// - `r = x(k·G) mod n`, `s = k⁻¹·(h + r·x) mod n`;
/// - low-s: `s > n/2` is replaced by `n − s` (the nonce is unchanged).
///
/// `p256`'s `sign_prehash` would derive `k` with HMAC-SHA-256 (the curve's
/// default digest): deterministic and valid, but not these bytes.
pub fn sign_raw_rs_64(signing_key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let digest = Sha3_256::digest(message);
    // z: the prehash as field bytes. 32 bytes is P-256's field size, so this is
    // the digest itself (bits2int needs no truncation).
    let z = FieldBytes::clone_from_slice(digest.as_slice());
    let x: &Scalar = signing_key.as_nonzero_scalar().as_ref();
    // bits2octets(h1) = int(h1) mod n, as 32 bytes (RFC 6979 §2.3.4). `rfc6979`
    // feeds `h` to the HMAC-DRBG as given, so the reduction happens here.
    let h_mod_n = <Scalar as Reduce<U256>>::reduce_bytes(&z).to_repr();
    let n: FieldBytes = <NistP256 as Curve>::ORDER.encode_field_bytes();
    let k_bytes = rfc6979::generate_k::<Sha3_256, _>(&x.to_repr(), &n, &h_mod_n, &[]);
    let k =
        Option::<Scalar>::from(Scalar::from_repr(k_bytes)).expect("RFC 6979 returns k in [1, n-1]");
    let (sig, _recovery_id) = ecdsa::hazmat::sign_prehashed::<NistP256, Scalar>(x, k, &z)
        .expect("r and s are non-zero for a k in [1, n-1] (except with negligible probability)");
    let sig: Signature = sig.normalize_s().unwrap_or(sig);
    let bytes = sig.to_bytes(); // FieldBytes||FieldBytes = r||s, 64 bytes
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

/// Verify a `raw-rs-64` ECDSA P-256 signature over SHA3-256 of `message`.
///
/// Returns `Ok(())` only if the signature verifies AND is low-s. A high-s
/// signature is REJECTED (never normalized) — anti-malleability, normative.
pub fn verify_raw_rs_64(
    public_key_sec1: &[u8],
    message: &[u8],
    sig_raw: &[u8],
) -> VerifyResult<()> {
    if sig_raw.len() != 64 {
        return Err(VerifyError::EcdsaMaterial(format!(
            "ECDSA-P256 signature must be raw-rs-64 (64 bytes r||s), got {}",
            sig_raw.len()
        )));
    }

    let sig = Signature::from_slice(sig_raw)
        .map_err(|e| VerifyError::EcdsaMaterial(format!("ECDSA-P256 signature parse: {e}")))?;

    // Low-s gate: reject high-s outright. `normalize_s()` returns `Some(_)` only
    // when the input was high-s (i.e. it had to be changed) → that means REJECT.
    if sig.normalize_s().is_some() {
        return Err(VerifyError::EcdsaMaterial(
            "ECDSA-P256 signature is high-s (rejected, not normalized)".to_string(),
        ));
    }

    let point = EncodedPoint::from_bytes(public_key_sec1).map_err(|e| {
        VerifyError::EcdsaMaterial(format!("ECDSA-P256 public key (SEC1) parse: {e}"))
    })?;
    let vk = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| VerifyError::EcdsaMaterial(format!("ECDSA-P256 public key invalid: {e}")))?;

    let digest = Sha3_256::digest(message);
    vk.verify_prehash(digest.as_slice(), &sig).map_err(|_| {
        VerifyError::EcdsaMaterial("ECDSA-P256 signature verification failed".to_string())
    })
}

/// Domain-separation info string for deriving the P-256 classical component of a
/// CERTCRYPT composite key from a 32-byte master seed. Load-bearing: the
/// production key-ceremony and the runtime MUST derive byte-identically, so this
/// constant and the derivation below are the single source of truth.
pub const P256_DERIVE_INFO: &[u8] = b"certcrypt/composite/p256/v1";

/// Deterministic P-256 signing key from a 32-byte master seed, via
/// HKDF-SHA3-256 with explicit domain separation (`P256_DERIVE_INFO`).
///
/// The same 32-byte seed also derives the ML-DSA-65 component (FIPS 204 KeyGen);
/// HKDF with a distinct `info` keeps the two derivations domain-separated so the
/// seed can safely materialize both. HKDF-Expand produces 48 bytes (oversampling
/// past the 32-byte field) which are reduced mod n — this avoids the modular bias
/// of reducing exactly 256 bits, and yields a scalar in [1, n-1] (0 mapped to 1).
///
/// This derivation is byte-stable and is the contract the production
/// key ceremony reproduces: the public key
/// published in the manifest MUST equal the one derived here from the same seed.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    use hkdf::Hkdf;
    use p256::elliptic_curve::bigint::{Encoding, NonZero, U256, U384};
    use p256::elliptic_curve::ops::Reduce;
    use sha3::Sha3_256;

    // HKDF-Extract(no salt) + Expand(info) → 48 bytes (oversampled for unbiased
    // reduction mod n; RFC 9380 §5 style).
    let hk = Hkdf::<Sha3_256>::new(None, seed);
    let mut okm = [0u8; 48];
    hk.expand(P256_DERIVE_INFO, &mut okm)
        .expect("HKDF-SHA3-256 expand to 48 bytes is valid");

    // Reduce the 384-bit OKM modulo the P-256 group order n (widened to 384 bits),
    // then narrow the (now < n) low 256 bits to a Scalar. `Scalar` only implements
    // Reduce<U256>, so we pre-reduce mod n in U384 to remove the bias first.
    // n for P-256, big-endian.
    const N_BE: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut n_384 = [0u8; 48];
    n_384[16..].copy_from_slice(&N_BE);
    let n = NonZero::new(U384::from_be_slice(&n_384)).expect("n is non-zero");
    let reduced_384 = U384::from_be_slice(&okm) % n; // < n < 2^256
    let low_256 = U256::from_be_slice(&reduced_384.to_be_bytes()[16..]);
    let mut scalar = <p256::Scalar as Reduce<U256>>::reduce(low_256);
    if scalar == p256::Scalar::from(0u64) {
        scalar = p256::Scalar::from(1u64);
    }
    SigningKey::from(p256::NonZeroScalar::new(scalar).expect("scalar mapped to non-zero"))
}

/// SEC1-encoded public key for a signing key. `compressed = true` → 33 bytes,
/// `false` → 65 bytes uncompressed.
pub fn public_key_sec1(signing_key: &SigningKey, compressed: bool) -> Vec<u8> {
    signing_key
        .verifying_key()
        .to_encoded_point(compressed)
        .as_bytes()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{NonZeroScalar, Scalar};

    fn fixed_key() -> SigningKey {
        // A fixed, nonzero scalar so tests are deterministic (no RNG).
        let bytes = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ];
        SigningKey::from_bytes((&bytes).into()).expect("valid scalar")
    }

    #[test]
    fn sign_then_verify_roundtrip_uncompressed_and_compressed() {
        let sk = fixed_key();
        let msg = b"the message that is signed (M')";
        let sig = sign_raw_rs_64(&sk, msg);
        assert_eq!(sig.len(), 64);
        assert!(verify_raw_rs_64(&public_key_sec1(&sk, false), msg, &sig).is_ok());
        assert!(verify_raw_rs_64(&public_key_sec1(&sk, true), msg, &sig).is_ok());
    }

    #[test]
    fn signature_is_low_s() {
        let sk = fixed_key();
        let sig = sign_raw_rs_64(&sk, b"low-s check");
        let parsed = Signature::from_slice(&sig).unwrap();
        assert!(parsed.normalize_s().is_none(), "signer must emit low-s");
    }

    #[test]
    fn rejects_tampered_message() {
        let sk = fixed_key();
        let sig = sign_raw_rs_64(&sk, b"original");
        assert!(verify_raw_rs_64(&public_key_sec1(&sk, false), b"tampered", &sig).is_err());
    }

    #[test]
    fn rejects_high_s_twin() {
        let sk = fixed_key();
        let msg = b"high-s rejection";
        let low = sign_raw_rs_64(&sk, msg);
        // Build the malleable high-s twin s' = n - s. Valid ECDSA math, must reject.
        let parsed = Signature::from_slice(&low).unwrap();
        let (r, s) = (parsed.r(), parsed.s());
        let neg_s: Scalar = -(*s.as_ref());
        let neg_s_nz = NonZeroScalar::new(neg_s).unwrap();
        let high = Signature::from_scalars(r, neg_s_nz).unwrap();
        let high_bytes = high.to_bytes();
        // Sanity: the twin must actually be high-s.
        assert!(high.normalize_s().is_some(), "twin must be high-s");
        assert!(
            verify_raw_rs_64(&public_key_sec1(&sk, false), msg, &high_bytes).is_err(),
            "high-s must be rejected"
        );
    }

    #[test]
    fn rejects_wrong_length() {
        let sk = fixed_key();
        assert!(verify_raw_rs_64(&public_key_sec1(&sk, false), b"x", &[0u8; 70]).is_err());
    }
}

#[cfg(test)]
mod cross_language_vector {
    //! A fixed, deterministic ECDSA-P256/SHA3-256/raw-rs-64 vector. RFC 6979 with
    //! H = SHA3-256 makes signing deterministic, so this triple is STABLE. The
    //! bytes are the ones the `ecdsa-p256-deterministic` construction yields for
    //! this key and message (re-derived by the conformance generator's own RFC 6979
    //! code); the family's own vectors are checked in
    //! `tests/ecdsa_p256_deterministic_parity.rs`.
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    const MSG: &[u8] = b"CERTCRYPT-Composite-Signature-v1 cross-check M'";
    // key = scalar [0x42;32]; MUST also verify in JS.
    const PK_B64: &str =
        "BDrThhqVYhOSUWu1k+8FWD7S5YZvXLYmCjAXI3/Ym5Cv0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0=";
    const SIG_B64: &str =
        "Zxfy/6j0Bl5MPPiQ5MHWSi8X8WrlUwqaOSE7O+b2kMFOHqxO7q5+0W3f10/V4r4isWSeamW1zK4p9buCH0YKoQ==";

    #[test]
    fn vector_is_deterministic_and_verifies() {
        let sk = SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let sig = sign_raw_rs_64(&sk, MSG);
        let pk = public_key_sec1(&sk, false);
        assert_eq!(B64.encode(pk).as_str(), PK_B64, "pubkey drifted");
        assert_eq!(
            B64.encode(sig).as_str(),
            SIG_B64,
            "signature drifted (RFC 6979 with HMAC-SHA3-256 must be deterministic)"
        );
        // Self-verify the pinned bytes.
        let pk = B64.decode(PK_B64).unwrap();
        let sig = B64.decode(SIG_B64).unwrap();
        assert!(verify_raw_rs_64(&pk, MSG, &sig).is_ok());
    }
}
