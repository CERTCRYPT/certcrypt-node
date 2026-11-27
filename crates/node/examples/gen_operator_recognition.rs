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

//! Mint a STABLE operator identity + its system-domain-signed operator.recognition/1
//! credential for a node of a local system domain, and print the three env vars
//! the node reads:
//!   CERTCRYPT_NODE_OPERATOR_SK_B64   (32-byte ML-DSA-65 seed)
//!   CERTCRYPT_NODE_OPERATOR_PK_B64
//!   CERTCRYPT_NODE_OPERATOR_CREDENTIAL_B64  (base64 JSON of the signed credential)
//!
//! The recognition is signed by the system domain's credential-signing key —
//! the one the domain's issuance service recognizes under the pinned
//! system_root_fingerprint — so the recognition gate (operator recognition is
//! mandatory at submit) accepts a node presenting it. Reads the credential seed
//! and the fingerprint from the environment; pair it with `gen_dev_foundation`,
//! which builds such a domain from the same seeds.
//!
//! Usage (with the domain's seeds and fingerprint in the environment):
//!   cargo run -p certcrypt-node --example gen_operator_recognition

#[path = "support/dev_seed.rs"]
mod dev_seed_mod;
use dev_seed_mod as dev_seed_impl;

use base64::Engine as _;
use capacity_artifacts::operator_recognition::{
    OperatorRecognitionCredentialV1, RecognitionInputs, RecognitionIssuer, RecognitionSignature,
    OPERATOR_KEY_ALG_ACTIVE, RECOGNITION_ARTIFACT_TYPE, SIGNATURE_ALG_ACTIVE,
};
use capacity_verify::mldsa;
use certcrypt_node_core::operator_receipt::OperatorIdentity;
use chrono::TimeZone;

fn main() {
    let b64 = base64::engine::general_purpose::STANDARD;

    // The system-domain credential key that signs recognitions.
    let cred = dev_seed_impl::load_credential().expect("load the credential key");
    let srf = std::env::var("CERTCRYPT_SYSTEM_ROOT_FINGERPRINT")
        .expect("CERTCRYPT_SYSTEM_ROOT_FINGERPRINT must be set");
    // The rules domain this credential is issued under. No default: it travels
    // inside signed bytes, so guessing one produces a credential that resolves
    // against the wrong domain.
    let rules_version = std::env::var("CERTCRYPT_RULES_VERSION")
        .expect("CERTCRYPT_RULES_VERSION must be set (the rules domain to issue under)");
    let system_id =
        std::env::var("CERTCRYPT_SYSTEM_ID").unwrap_or_else(|_| "certcrypt".to_string());

    // A fresh, stable operator keypair for this node.
    let operator = OperatorIdentity::generate();
    let operator_pk_b64 = b64.encode(&operator.public_key);

    let valid_from = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let valid_until = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
    let recognition_issuer = RecognitionIssuer {
        kid: cred.kid.clone(),
        manifest_sequence: 1,
    };
    let inputs = RecognitionInputs {
        system_root_fingerprint: srf.clone(),
        rules_version: rules_version.clone(),
        operator_public_key: operator_pk_b64.clone(),
        operator_key_alg: OPERATOR_KEY_ALG_ACTIVE.to_string(),
        valid_from,
        valid_until,
        recognition_issuer: recognition_issuer.clone(),
    };
    let recognition_id =
        OperatorRecognitionCredentialV1::compute_recognition_id(&inputs, &operator.operator_id)
            .expect("recognition id");

    let mut credential = OperatorRecognitionCredentialV1 {
        artifact_type: RECOGNITION_ARTIFACT_TYPE.to_string(),
        system_id,
        rules_version,
        system_root_fingerprint: srf,
        recognition_id,
        operator_id: operator.operator_id.clone(),
        operator_public_key: operator_pk_b64.clone(),
        operator_key_alg: OPERATOR_KEY_ALG_ACTIVE.to_string(),
        valid_from,
        valid_until,
        recognition_issuer,
        signature: RecognitionSignature {
            signature_alg: SIGNATURE_ALG_ACTIVE.to_string(),
            signature_b64: String::new(),
        },
    };
    let signing_bytes = credential
        .signing_bytes()
        .expect("credential signing bytes");
    let sig = mldsa::sign_detached(&cred.secret_key, &signing_bytes).expect("sign credential");
    credential.signature.signature_b64 = b64.encode(&sig);

    let cred_json = serde_json::to_vec(&credential).expect("serialize credential");

    eprintln!("operator_id = {}", operator.operator_id);
    eprintln!("recognition signed by kid = {}", cred.kid);
    println!(
        "CERTCRYPT_NODE_OPERATOR_SK_B64={}",
        b64.encode(operator.secret_key())
    );
    println!("CERTCRYPT_NODE_OPERATOR_PK_B64={}", operator_pk_b64);
    println!(
        "CERTCRYPT_NODE_OPERATOR_CREDENTIAL_B64={}",
        b64.encode(&cred_json)
    );
}
