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

//! Emit a fresh, STABLE operator keypair for the node in the exact format the
//! node's signer expects: the secret is a 32-byte ML-DSA-65 SEED (not the
//! expanded key). Prints the public key and the seed as base64 so they can be
//! seated as CERTCRYPT_NODE_OPERATOR_PK_B64 / _SK_B64. The matching
//! `operator.recognition/1` credential is then issued for the printed public key.
//!
//! Usage (from certcrypt-node/):
//!   cargo run -p certcrypt-node --example gen_operator_key

use base64::Engine as _;
use capacity_verify::mldsa;

fn main() {
    let (public_key, seed) = mldsa::keypair(); // seed is the 32-byte secret
    let b64 = base64::engine::general_purpose::STANDARD;
    println!("CERTCRYPT_NODE_OPERATOR_SK_B64={}", b64.encode(&seed));
    println!("CERTCRYPT_NODE_OPERATOR_PK_B64={}", b64.encode(&public_key));
}
