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

//! The verification package transports a `base_certificate` (CCSP/1 Issued
//! plane) VERBATIM, so a third party can verify the certificate against its
//! original material offline from the package alone — without the issuer SDK.
//!
//! The node owns none of the certificate's internals (Model A: the issuer SDK
//! produced and signed it); the package carries it as opaque transport. These
//! tests pin that contract: (a) a certificate handed in as `base_certificate`
//! comes back byte-identical through the package, and (b) every package carries
//! it, together with `verification_context` (verification-package/1 §9.1).

use certcrypt_node_core::{assemble_verification_package, PackageInputs};
use serde_json::{json, Value};

/// A `base_certificate` of the exact shape the issuer SDK mints (schema,
/// payload.anchor with subjects[], composite issuer signature). We only need it
/// to be an opaque JSON `Value` here — the node never reinterprets it.
fn sample_base_certificate() -> Value {
    json!({
        "schema": "certcrypt-certificate",
        "payload": {
            "anchor": {
                "issued_at": "2026-07-07T12:00:00Z",
                "nonce_hex": "3ff2f4164f4fdfb06424993687f975e26e4a12ddc90467afdb80f5939baf6af2",
                "root_id": "4641cb3850fdfde06875bed9382b2afeb2a108ac48ef32d4e196d456a0059635",
                "subjects": [
                    { "profile": "subject.binary/1",
                      "commitment_digest_hex": "4b569a4574dd867a41a48c53715d122711bc3c74586b78e94cbdb744ba6787b0" }
                ]
            },
            "anchor_commitment_digest_hex": "fd58be00e7ca5b4deecc48d3bd39ff64b7c9a2517843d6e796b79a85d707b224",
            "system_id": "certcrypt",
            "rules_version": "rules/conformance"
        },
        "payload_canon_digest_hex": "1c793b940a153b736903bbefb286e8654f34797606292ad629173c72c5f50275",
        "signatures": [{
            "role": "issuer",
            "sig_target": "payload_canon_digest_hex",
            "alg": "certcrypt-composite-p256-mldsa65-v1",
            "mode": "AND",
            "signatures": [
                { "alg": "ECDSA-P256-SHA3-256", "encoding": "raw-rs-64", "low_s": true, "sig_b64": "AAAA" },
                { "alg": "ML-DSA-65", "sig_b64": "BBBB" }
            ],
            "signer": { "id": "issuer:test", "pub_p256_b64": "CCCC", "pub_mldsa_b64": "DDDD" }
        }]
    })
}

fn base_inputs(base_certificate: Value) -> PackageInputs {
    PackageInputs {
        base_certificate,
        independence_proof: json!({ "proof_version": "independence.proof/1" }),
        rules_version: "rules/conformance".into(),
        system_id: "certcrypt".into(),
        capacity_evidence: None,
        commitment_inclusion_proof: None,
        settlement_material: None,
        settlement_reference: None,
    }
}

#[test]
fn package_transports_base_certificate_verbatim() {
    let cert = sample_base_certificate();
    let pkg = assemble_verification_package(base_inputs(cert.clone()));

    // The certificate is carried unchanged (opaque transport — no reinterpretation).
    assert_eq!(
        pkg.base_certificate, cert,
        "base_certificate must be transported verbatim"
    );

    // And it survives a canonical serialize→parse round-trip identically, so a
    // third-party consumer reconstructs the exact bytes the issuer signed.
    let canonical = pkg.to_canonical_bytes().expect("canonical serialize");
    let reparsed: Value = serde_json::from_slice(&canonical).expect("reparse");
    assert_eq!(
        reparsed.get("base_certificate"),
        Some(&cert),
        "base_certificate must round-trip through the package unchanged"
    );
}

#[test]
fn every_package_carries_base_certificate_and_context() {
    let pkg = assemble_verification_package(base_inputs(sample_base_certificate()));
    let canonical = pkg.to_canonical_bytes().expect("canonical serialize");
    let reparsed: Value = serde_json::from_slice(&canonical).expect("reparse");
    assert!(reparsed.get("base_certificate").is_some());
    assert_eq!(
        reparsed["verification_context"],
        json!({ "rules_version": "rules/conformance", "system_id": "certcrypt" })
    );
    // Members a package does not define are never written (verification-package/1 §9.4).
    for absent in [
        "version",
        "target",
        "supporting_material",
        "system_foundation",
    ] {
        assert!(
            reparsed.get(absent).is_none(),
            "{absent} is not a package member"
        );
    }
}
