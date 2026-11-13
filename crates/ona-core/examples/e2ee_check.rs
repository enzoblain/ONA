//! One real encrypted call to NEAR AI Cloud through a relay that holds the API key.
//!
//! It checks that the gateway accepts the encryption version the client uses (3 by default). The client never sees the
//! API key: run a relay that holds it, then point this at the relay.
//!
//! ```text
//! ONA_CHECK_RELAY_URL=http://127.0.0.1:8787 ONA_CHECK_MODEL=<model> cargo run -p ona-core --example e2ee_check
//! ONA_CHECK_VERSION=2 ...   # the same call with encryption version 2, for comparison
//! ```
//!
//! Each run spends at most `ONA_CHECK_MAX_TOKENS` (default 200) reply tokens plus the prompt.
//!
//! The model key is checked as in the app (`attestation::near_ai_verifier`): Intel's collateral is fetched from Intel's
//! service, through Tor when `ONA_TOR_SOCKS` is set, like the request to the relay.

use ona_core::attestation::near_ai_verifier;
use ona_core::e2ee::{E2eeClient, EncryptionVersion};
use ona_core::tor::Network;

fn main() {
    let relay = std::env::var("ONA_CHECK_RELAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".to_string());
    let model = match std::env::var("ONA_CHECK_MODEL") {
        Ok(model) if !model.is_empty() => model,
        _ => {
            eprintln!("set ONA_CHECK_MODEL to a model the relay allows");
            std::process::exit(2);
        }
    };
    let max_tokens: u32 = std::env::var("ONA_CHECK_MAX_TOKENS").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
    let version = match std::env::var("ONA_CHECK_VERSION").as_deref() {
        Ok("2") => EncryptionVersion::V2,
        _ => EncryptionVersion::V3,
    };
    let label = if version == EncryptionVersion::V2 { "2" } else { "3" };

    let network = Network::from_env().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });
    let transport = network.transport(&relay).unwrap_or_else(|e| {
        eprintln!("relay URL: {e}");
        std::process::exit(2);
    });
    let mut client =
        E2eeClient::new(transport, near_ai_verifier(&network), &model, max_tokens, u64::from(max_tokens) + 1_000)
            .with_encryption_version(version);
    println!("encryption version {label}, model {model}, relay {relay}");
    match client.chat("Reply with one short sentence: what is 2 + 2?") {
        Ok(reply) => {
            println!(
                "OK: model key from an Intel-verified quote, decrypted reply, valid signature, {} tokens",
                reply.tokens_used
            );
            println!("reply: {}", reply.content);
        }
        Err(error) => {
            println!("FAILED: {error}");
            std::process::exit(1);
        }
    }
}
