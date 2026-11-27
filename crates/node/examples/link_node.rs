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

use std::time::{Duration, Instant};

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
    Engine as _,
};
use capacity_verify::mldsa;
use certcrypt_node::UpstreamClient;
use certcrypt_node_core::operator_receipt::OperatorIdentity;
use sha3::{Digest, Sha3_256};

fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name).map_err(|_| anyhow::anyhow!("{name} is required"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api_url = required("CERTCRYPT_API_URL")?;
    let sk = B64.decode(required("CERTCRYPT_NODE_OPERATOR_SK_B64")?)?;
    let pk_b64 = required("CERTCRYPT_NODE_OPERATOR_PK_B64")?;
    let pk = B64.decode(&pk_b64)?;
    let identity = OperatorIdentity::from_keypair(pk, sk);

    eprintln!("\nLocal node identity — compare these values in the console:");
    eprintln!("operator_id: {}", identity.operator_id);
    eprintln!(
        "key fingerprint: {}",
        hex::encode(Sha3_256::digest(&identity.public_key))
    );
    eprintln!();

    let (_, nonce) = mldsa::keypair();
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
    let open_message = format!("certcrypt:node-link-request:1|{pk_b64}|{nonce_b64}");
    let client = UpstreamClient::new(api_url);
    let opened = client
        .open_node_link(
            &pk_b64,
            &nonce_b64,
            &identity
                .sign_challenge(open_message.as_bytes())
                .map_err(anyhow::Error::msg)?,
        )
        .await?;

    eprintln!(
        "\nIf the integration creation page is already open, return to it and enter this code:"
    );
    eprintln!("Code: {}", opened.user_code);
    eprintln!("If you started outside the console, open this URL instead:");
    eprintln!("{}\n", opened.verification_uri);

    let claim_message = format!(
        "certcrypt:node-link-claim:1|{}|{}|{}",
        opened.link_request_id, identity.operator_id, opened.claim_token
    );
    let possession = identity
        .sign_challenge(claim_message.as_bytes())
        .map_err(anyhow::Error::msg)?;
    let deadline = Instant::now() + Duration::from_secs(opened.expires_in_seconds);
    loop {
        let claimed = match client
            .claim_node_link(&opened.link_request_id, &opened.claim_token, &possession)
            .await
        {
            Ok((_, claimed)) => claimed,
            Err(error) if error.is_transient() && Instant::now() < deadline => {
                let retry_after = error.retry_after().unwrap_or(Duration::from_secs(2));
                eprintln!(
                    "certcrypt-node: link backend temporarily unavailable; retrying in {}s",
                    retry_after.as_secs()
                );
                tokio::time::sleep(retry_after).await;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(credential) = claimed.credential {
            let encoded = B64.encode(serde_json::to_vec(&credential)?);
            println!("CERTCRYPT_NODE_OPERATOR_CREDENTIAL_B64={encoded}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("node link request expired before it was linked");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
