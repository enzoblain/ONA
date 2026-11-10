//! Passes end-to-end encrypted calls to NEAR AI Cloud. The relay holds the API key and spends one
//! request token per chat.
//!
//! An honest relay only handles ciphertext, but the content is not protected from a dishonest one:
//! with encryption version 2 the client key travels in a header, so a relay can replace it with its
//! own and read the reply. The model's signature can reveal this afterwards, it cannot prevent it.
//!
//! Bodies are forwarded byte for byte, because the model's signature covers the exact bytes. So
//! the token limit cannot be rewritten here: a request that breaks the policy is refused instead.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::ErrorKind;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Number, Value};

use crate::http::Request;
use crate::{Chain, Relay, Store, Upstream};

/// Most bytes in a chat body. Far above what fits the reply budget, which withholds any call over
/// twice `max_tokens`, so this only stops calls that could never be paid for.
pub const MAX_CHAT_BODY: usize = 64 * 1024;
/// Attestations and signatures are free, so they are limited across all clients. A chat uses two.
pub const DEFAULT_FREE_ROUTES_PER_MINUTE: u32 = 600;
const MAX_SIGNATURE_ID: usize = 128;
const KEY_HEX_LEN: usize = 64;
const NONCE_HEX_LEN: usize = 64;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(90);
const MINUTE: Duration = Duration::from_secs(60);

const FORWARDED_HEADERS: [&str; 7] = [
    "Content-Type",
    "X-Signing-Algo",
    "X-Client-Pub-Key",
    "X-Model-Pub-Key",
    "X-Encryption-Version",
    "x-no-aliasing",
    "Accept-Encoding",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendFailure {
    /// The service refused the connection: nothing was sent, so nothing was billed.
    ConnectionRefused,
    /// Anything else. The call may have reached the model.
    Other(String),
}

pub trait Backend {
    fn forward(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), BackendFailure>;
}

/// NEAR AI Cloud over HTTPS. Only this type ever holds the API key.
#[derive(Clone)]
pub struct NearAiBackend {
    base: String,
    api_key: String,
    agent: ureq::Agent,
}

impl NearAiBackend {
    pub fn new(base: &str, api_key: String) -> Self {
        Self::with_timeout(base, api_key, UPSTREAM_TIMEOUT)
    }

    /// `timeout` covers the whole call, from connecting to reading the end of the reply.
    pub fn with_timeout(base: &str, api_key: String, timeout: Duration) -> Self {
        let agent: ureq::Agent =
            ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(timeout)).build().into();
        Self { base: base.trim_end_matches('/').to_string(), api_key, agent }
    }
}

fn failure(error: ureq::Error) -> BackendFailure {
    match &error {
        ureq::Error::Io(io) if io.kind() == ErrorKind::ConnectionRefused => BackendFailure::ConnectionRefused,
        _ => BackendFailure::Other(error.to_string()),
    }
}

impl Backend for NearAiBackend {
    fn forward(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), BackendFailure> {
        let url = format!("{}{target}", self.base);
        let authorization = format!("Bearer {}", self.api_key);
        let mut response = if method == "POST" {
            let mut request = self.agent.post(url).header("Authorization", &authorization);
            for (name, value) in headers {
                request = request.header(name, value);
            }
            request.send(body).map_err(failure)?
        } else {
            let mut request = self.agent.get(url).header("Authorization", &authorization);
            for (name, value) in headers {
                request = request.header(name, value);
            }
            request.call().map_err(failure)?
        };
        let status = response.status().as_u16();
        let reply = response.body_mut().read_to_vec().map_err(failure)?;
        Ok((status, reply))
    }
}

#[derive(Debug, Clone, Default)]
pub struct GatewayPolicy {
    pub models: BTreeSet<String>,
    pub free_routes_per_minute: u32,
}

impl GatewayPolicy {
    pub fn new(models: BTreeSet<String>) -> Self {
        Self { models, free_routes_per_minute: DEFAULT_FREE_ROUTES_PER_MINUTE }
    }
}

/// Counts calls in fixed one-minute windows.
#[derive(Default)]
pub(crate) struct MinuteWindow {
    start: Option<Instant>,
    count: u32,
}

impl MinuteWindow {
    fn allow(&mut self, now: Instant, limit: u32) -> bool {
        if self.start.is_none_or(|start| now.duration_since(start) >= MINUTE) {
            self.start = Some(now);
            self.count = 0;
        }
        if self.count >= limit {
            return false;
        }
        self.count += 1;
        true
    }
}

fn refuse(status: u16, message: &str) -> (u16, Vec<u8>) {
    (status, json!({"error": message}).to_string().into_bytes())
}

fn safe_target(target: &str) -> bool {
    !target.contains("..") && target.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./?=&:".contains(&b))
}

fn filtered_headers(request: &Request) -> Vec<(String, String)> {
    FORWARDED_HEADERS
        .iter()
        .filter_map(|name| request.header(name).map(|value| (name.to_string(), value.to_string())))
        .collect()
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_signature_target(target: &str) -> bool {
    target
        .strip_prefix("/v1/signature/")
        .and_then(|rest| rest.strip_suffix("?signing_algo=ed25519"))
        .is_some_and(|id| {
            !id.is_empty()
                && id.len() <= MAX_SIGNATURE_ID
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

fn valid_attestation_target(policy: &GatewayPolicy, target: &str) -> bool {
    let Some(query) = target.strip_prefix("/v1/attestation/report?") else {
        return false;
    };
    let mut params = BTreeMap::new();
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            return false;
        };
        if params.insert(name, value).is_some() {
            return false;
        }
    }
    params.len() == 5
        && params.get("model").is_some_and(|model| policy.models.contains(*model))
        && params.get("provider") == Some(&"near")
        && params.get("signing_algo") == Some(&"ed25519")
        && params.get("include_tls_fingerprint") == Some(&"false")
        && params.get("nonce").is_some_and(|nonce| nonce.len() == NONCE_HEX_LEN && is_lower_hex(nonce))
}

/// JSON parsed with every duplicated object key refused, at any depth.
struct StrictJson(Value);

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON without duplicated keys")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v).map(Value::Number).ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictJson(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(A::Error::custom("duplicated key"));
            }
            let StrictJson(value) = map.next_value()?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(StrictJson)
    }
}

fn has_exactly(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn single_encrypted_message(value: &Value) -> bool {
    let Some([message]) = value.as_array().map(Vec::as_slice) else {
        return false;
    };
    message.as_object().is_some_and(|object| has_exactly(object, &["role", "content"]))
        && message["role"] == "user"
        && message["content"]
            .as_str()
            .is_some_and(|content| !content.is_empty() && content.len() % 2 == 0 && is_lower_hex(content))
}

fn is_key_hex(value: Option<&str>) -> bool {
    value.is_some_and(|key| key.len() == KEY_HEX_LEN && is_lower_hex(key))
}

fn check_encryption_headers(request: &Request) -> Result<(), (u16, Vec<u8>)> {
    let complete = request.header("X-Signing-Algo") == Some("ed25519")
        && request.header("X-Encryption-Version") == Some("2")
        && is_key_hex(request.header("X-Client-Pub-Key"))
        && is_key_hex(request.header("X-Model-Pub-Key"));
    if complete {
        Ok(())
    } else {
        Err(refuse(400, "encryption headers are missing or invalid"))
    }
}

/// What is left to do once a call has been accepted.
pub struct Forward {
    is_chat: bool,
    /// The request token spent by this call, if any.
    token: Option<String>,
    headers: Vec<(String, String)>,
}

impl<S: Store, C: Chain, U: Upstream> Relay<S, C, U> {
    /// Everything is checked here, because a request refused later would already have cost a token.
    fn check_chat_policy(&self, policy: &GatewayPolicy, request: &Request) -> Result<(), (u16, Vec<u8>)> {
        if request.body.len() > MAX_CHAT_BODY {
            return Err(refuse(413, "chat body too large"));
        }
        let StrictJson(value) =
            serde_json::from_slice(&request.body).map_err(|_| refuse(400, "body is not strict JSON"))?;
        let shape_is_exact =
            value.as_object().is_some_and(|object| has_exactly(object, &["model", "messages", "stream", "max_tokens"]));
        if !shape_is_exact {
            return Err(refuse(400, "body must hold exactly model, messages, stream and max_tokens"));
        }
        if !value["model"].as_str().is_some_and(|m| policy.models.contains(m)) {
            return Err(refuse(400, "model not allowed"));
        }
        if value["stream"] != json!(false) {
            return Err(refuse(400, "stream must be false"));
        }
        if !matches!(value["max_tokens"].as_u64(), Some(n) if n > 0 && n <= u64::from(self.config.max_tokens_per_request)) {
            return Err(refuse(400, "max_tokens is missing or over the limit"));
        }
        if !single_encrypted_message(&value["messages"]) {
            return Err(refuse(400, "messages must be one encrypted user message"));
        }
        check_encryption_headers(request)
    }

    /// First half of a call, before the service is contacted. A chat spends its token here, after
    /// the policy check so that a malformed request does not cost the user anything.
    pub fn gateway_begin(&mut self, policy: &GatewayPolicy, request: &Request) -> Result<Forward, (u16, Vec<u8>)> {
        if !safe_target(&request.target) {
            return Err(refuse(400, "invalid target"));
        }
        let headers = filtered_headers(request);
        if request.method == "POST" && request.target == "/v1/chat/completions" {
            self.check_chat_policy(policy, request)?;
            let Some(encoded) = request.header("X-Ona-Token") else {
                return Err(refuse(401, "missing request token"));
            };
            let token = self.check_request_token(encoded).map_err(|(status, body)| (status, body.to_string().into_bytes()))?;
            return Ok(Forward { is_chat: true, token: Some(token), headers });
        }
        let is_free = request.method == "GET"
            && (valid_signature_target(&request.target) || valid_attestation_target(policy, &request.target));
        if !is_free {
            return Err(refuse(404, "not found"));
        }
        if !self.free_routes.allow(Instant::now(), policy.free_routes_per_minute) {
            return Err(refuse(429, "too many requests"));
        }
        Ok(Forward { is_chat: false, token: None, headers })
    }

    /// The request token comes back only when the failure proves the call was not billed.
    fn release_token(&mut self, forward: &Forward) {
        if let Some(token) = &forward.token {
            if let Err(e) = self.store.release_request_token(token) {
                eprintln!("request token not returned: {e}");
            }
        }
    }

    /// Second half of a call, with what the service answered.
    pub fn gateway_end(&mut self, forward: Forward, outcome: Result<(u16, Vec<u8>), BackendFailure>) -> (u16, Vec<u8>) {
        let (status, reply) = match outcome {
            Ok(result) => result,
            Err(failure) => {
                if failure == BackendFailure::ConnectionRefused {
                    self.release_token(&forward);
                }
                return refuse(502, "model service unavailable");
            }
        };
        if status != 200 {
            if matches!(status, 401 | 402 | 429) {
                self.release_token(&forward);
            }
            // The service's own error text can describe the relay's account.
            return refuse(status, "model service error");
        }
        if forward.is_chat {
            let used = serde_json::from_slice::<Value>(&reply)
                .ok()
                .and_then(|v| v["usage"]["total_tokens"].as_u64());
            let limit = u64::from(self.config.max_tokens_per_request);
            // Last resort, paid for already: the count covers the prompt too.
            if used.is_none_or(|n| n > limit.saturating_mul(2)) {
                return refuse(402, "reply withheld: over the request budget");
            }
        }
        (status, reply)
    }

    /// Handles one call for NEAR AI. Attestations and signatures are free, within a global limit.
    pub fn gateway<B: Backend>(
        &mut self,
        backend: &mut B,
        policy: &GatewayPolicy,
        request: &Request,
    ) -> (u16, Vec<u8>) {
        let forward = match self.gateway_begin(policy, request) {
            Ok(forward) => forward,
            Err(response) => return response,
        };
        let outcome = backend.forward(&request.method, &request.target, &forward.headers, &request.body);
        self.gateway_end(forward, outcome)
    }

    /// As `gateway`, for several threads: the relay is not locked while the service is called.
    pub fn gateway_shared<B: Backend>(
        relay: &Mutex<Self>,
        backend: &mut B,
        policy: &GatewayPolicy,
        request: &Request,
    ) -> (u16, Vec<u8>) {
        let started = match relay.lock() {
            Ok(mut guard) => guard.gateway_begin(policy, request),
            Err(_) => return refuse(503, "relay unavailable"),
        };
        let forward = match started {
            Ok(forward) => forward,
            Err(response) => return response,
        };
        let outcome = backend.forward(&request.method, &request.target, &forward.headers, &request.body);
        match relay.lock() {
            Ok(mut guard) => guard.gateway_end(forward, outcome),
            Err(_) => refuse(503, "relay unavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_free_route_window_resets_after_a_minute() {
        let mut window = MinuteWindow::default();
        let start = Instant::now();
        assert!(window.allow(start, 2));
        assert!(window.allow(start + Duration::from_secs(59), 2));
        assert!(!window.allow(start + Duration::from_secs(59), 2));
        assert!(window.allow(start + MINUTE, 2));
    }
}
