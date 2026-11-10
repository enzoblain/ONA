//! Passes end-to-end encrypted calls to NEAR AI Cloud. The relay holds the API key, spends one
//! request token per chat, and never sees a prompt or a reply in clear.
//!
//! Bodies are forwarded byte for byte, because the model's signature covers the exact bytes. So
//! the token limit cannot be rewritten here: a request that breaks the policy is refused instead.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::http::Request;
use crate::{Chain, Relay, Store, Upstream};

const FORWARDED_HEADERS: [&str; 7] = [
    "Content-Type",
    "X-Signing-Algo",
    "X-Client-Pub-Key",
    "X-Model-Pub-Key",
    "X-Encryption-Version",
    "x-no-aliasing",
    "Accept-Encoding",
];

pub trait Backend {
    fn forward(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String>;
}

/// NEAR AI Cloud over HTTPS. Only this type ever holds the API key.
pub struct NearAiBackend {
    base: String,
    api_key: String,
    agent: ureq::Agent,
}

impl NearAiBackend {
    pub fn new(base: &str, api_key: String) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        Self { base: base.trim_end_matches('/').to_string(), api_key, agent }
    }
}

impl Backend for NearAiBackend {
    fn forward(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let url = format!("{}{target}", self.base);
        let authorization = format!("Bearer {}", self.api_key);
        let mut response = if method == "POST" {
            let mut request = self.agent.post(url).header("Authorization", &authorization);
            for (name, value) in headers {
                request = request.header(name, value);
            }
            request.send(body).map_err(|e| e.to_string())?
        } else {
            let mut request = self.agent.get(url).header("Authorization", &authorization);
            for (name, value) in headers {
                request = request.header(name, value);
            }
            request.call().map_err(|e| e.to_string())?
        };
        let status = response.status().as_u16();
        let reply = response.body_mut().read_to_vec().map_err(|e| e.to_string())?;
        Ok((status, reply))
    }
}

#[derive(Debug, Clone, Default)]
pub struct GatewayPolicy {
    pub models: BTreeSet<String>,
}

fn refuse(status: u16, message: &str) -> (u16, Vec<u8>) {
    (status, json!({"error": message}).to_string().into_bytes())
}

fn safe_target(target: &str) -> bool {
    !target.contains("..")
        && target.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./?=&:%".contains(&b))
}

fn filtered_headers(request: &Request) -> Vec<(String, String)> {
    FORWARDED_HEADERS
        .iter()
        .filter_map(|name| request.header(name).map(|value| (name.to_string(), value.to_string())))
        .collect()
}

impl<S: Store, C: Chain, U: Upstream> Relay<S, C, U> {
    fn check_chat_policy(&self, policy: &GatewayPolicy, body: &[u8]) -> Result<(), (u16, Vec<u8>)> {
        let value: Value = serde_json::from_slice(body).map_err(|_| refuse(400, "body is not JSON"))?;
        let allowed = value["model"].as_str().is_some_and(|m| policy.models.contains(m));
        if !allowed {
            return Err(refuse(400, "model not allowed"));
        }
        if value["stream"] != json!(false) {
            return Err(refuse(400, "stream must be false"));
        }
        match value["max_tokens"].as_u64() {
            Some(n) if n > 0 && n <= u64::from(self.config.max_tokens_per_request) => Ok(()),
            _ => Err(refuse(400, "max_tokens is missing or over the limit")),
        }
    }

    /// Handles one call for NEAR AI. Attestations and signatures are free. A chat spends a token,
    /// after the policy check so that a malformed request does not cost the user anything.
    pub fn gateway<B: Backend>(
        &mut self,
        backend: &mut B,
        policy: &GatewayPolicy,
        request: &Request,
    ) -> (u16, Vec<u8>) {
        if !safe_target(&request.target) {
            return refuse(400, "invalid target");
        }
        let is_chat = request.method == "POST" && request.target == "/v1/chat/completions";
        let is_free = request.method == "GET"
            && (request.target.starts_with("/v1/attestation/report?")
                || request.target.starts_with("/v1/signature/"));
        if !is_chat && !is_free {
            return refuse(404, "not found");
        }
        if is_chat {
            if let Err(response) = self.check_chat_policy(policy, &request.body) {
                return response;
            }
            let Some(token) = request.header("X-Ona-Token") else {
                return refuse(401, "missing request token");
            };
            if let Err((status, body)) = self.check_request_token(token) {
                return (status, body.to_string().into_bytes());
            }
        }

        let headers = filtered_headers(request);
        let (status, reply) = match backend.forward(&request.method, &request.target, &headers, &request.body) {
            Ok(result) => result,
            Err(_) => return refuse(502, "model service unavailable"),
        };
        if is_chat && status == 200 {
            let used = serde_json::from_slice::<Value>(&reply)
                .ok()
                .and_then(|v| v["usage"]["total_tokens"].as_u64());
            let limit = u64::from(self.config.max_tokens_per_request);
            // The count covers the prompt too, so a large prompt also reaches this limit.
            if used.is_none_or(|n| n > limit.saturating_mul(2)) {
                return refuse(402, "reply withheld: over the request budget");
            }
        }
        (status, reply)
    }
}
