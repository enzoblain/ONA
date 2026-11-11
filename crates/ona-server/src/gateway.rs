//! Passes end-to-end encrypted calls to NEAR AI Cloud. The relay holds the API key and spends one
//! request token per chat.
//!
//! An honest relay only handles ciphertext. With encryption version 2 the content is not protected
//! from a dishonest one: the client key travels in a header, so a relay can replace it with its own
//! and read the reply. Version 3 binds the request to that key, so a replaced key makes the request
//! undecryptable. Whether NEAR AI accepts version 3 is not verified. Both versions are passed on.
//!
//! Bodies are forwarded byte for byte, because the model's signature covers the exact bytes. So
//! the token limit cannot be rewritten here: a request that breaks the policy is refused instead.
//!
//! Attestations and signatures cost the relay a call but no token. So an attestation needs an unused
//! request token, which it does not spend, and each token gets a few; a signature needs the token
//! spent on the chat it signs, and is never refused by the global limit, so a paid chat can always
//! collect its signature.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Number, Value};

use crate::http::Request;
use crate::{Chain, Relay, Store, Upstream, Verifier};

/// Most bytes in a chat body, whatever the budget.
pub const MAX_CHAT_BODY: usize = 64 * 1024;
/// Bytes the client's encryption adds to a message: ephemeral key (32), nonce (24) and tag (16),
/// as written by `ona-core` `encrypt_with_aad`.
pub const ENCRYPTION_OVERHEAD: usize = 72;
/// Global limit on attestations, across all clients, as a last net.
pub const DEFAULT_FREE_ROUTES_PER_MINUTE: u32 = 600;
/// Attestations one unused request token gives.
pub const ATTESTATIONS_PER_TOKEN: u8 = 4;
/// Signature fetches one paid chat gives, within `TICKET_LIFETIME`.
pub const SIGNATURES_PER_CHAT: u8 = 4;
/// Tokens the model's chat template adds around the message. An estimate, not measured.
pub const TEMPLATE_TOKENS: u64 = 64;
const TICKET_LIFETIME: Duration = Duration::from_secs(600);
/// Most tokens and paid chats followed at once. Beyond that, new ones are refused until old ones expire.
const MAX_TRACKED: usize = 65_536;
/// Most bytes read from a model reply.
const MAX_REPLY: u64 = 4 * 1024 * 1024;
const MAX_SIGNATURE_ID: usize = 128;
const KEY_HEX_LEN: usize = 64;
const NONCE_HEX_LEN: usize = 64;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(90);
const MINUTE: Duration = Duration::from_secs(60);

/// Client headers passed on with a chat, after `check_encryption_headers`. `Content-Type` and
/// `Accept-Encoding` are set by the relay, and free routes pass on no client header.
const FORWARDED_HEADERS: [&str; 5] =
    ["X-Signing-Algo", "X-Client-Pub-Key", "X-Model-Pub-Key", "X-Encryption-Version", "x-no-aliasing"];
/// Encryption versions passed on. A version this relay does not know is refused, never guessed.
const ENCRYPTION_VERSIONS: [&str; 2] = ["2", "3"];

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
        // No redirect: the service could otherwise send the encrypted body to another host.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .build()
            .into();
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
        let reply = response.body_mut().with_config().limit(MAX_REPLY).read_to_vec().map_err(failure)?;
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

/// What a paid chat leaves behind: the right to fetch the signature of its reply a few times.
struct Ticket {
    reply_id: String,
    left: u8,
    issued: Instant,
}

/// State of the free routes, kept in memory only. Attestation counts are never reset while the relay
/// runs: a token's entry goes only when the token is spent. A restart gives unused tokens their
/// attestations back, and paid chats from before the restart lose their tickets.
#[derive(Default)]
pub(crate) struct FreeRoutes {
    window: MinuteWindow,
    /// Attestations served per unused request token.
    attestations: HashMap<String, u8>,
    tickets: HashMap<String, Ticket>,
}

impl FreeRoutes {
    /// Holding `MAX_TRACKED` unused tokens that each asked for an attestation fills the table: new
    /// tokens are then refused attestations until some are spent. Each token was paid for with a share
    /// of a credit, so filling it costs `MAX_TRACKED / tokens_per_credit` credits (655 at 100 per credit).
    fn admit_attestation(&mut self, token: &str, now: Instant, limit: u32) -> Result<(), (u16, Vec<u8>)> {
        if !self.attestations.contains_key(token) && self.attestations.len() >= MAX_TRACKED {
            return Err(refuse(429, "too many requests"));
        }
        let served = self.attestations.get(token).copied().unwrap_or(0);
        if served >= ATTESTATIONS_PER_TOKEN {
            return Err(refuse(429, "attestations used up for this request token"));
        }
        if !self.window.allow(now, limit) {
            return Err(refuse(429, "too many requests"));
        }
        self.attestations.insert(token.to_string(), served + 1);
        Ok(())
    }

    /// A spent token can no longer ask for attestations, so its count is dropped.
    fn token_spent(&mut self, token: &str) {
        self.attestations.remove(token);
    }

    fn admit_signature(&mut self, token: &str, id: &str, now: Instant) -> Result<(), (u16, Vec<u8>)> {
        let missing = || refuse(401, "a signature needs the request token of the chat it signs");
        let ticket = self.tickets.get_mut(token).ok_or_else(missing)?;
        if now.duration_since(ticket.issued) >= TICKET_LIFETIME || ticket.reply_id != id {
            return Err(missing());
        }
        if ticket.left == 0 {
            return Err(refuse(429, "signature fetches used up for this chat"));
        }
        ticket.left -= 1;
        Ok(())
    }

    /// A fetch the service did not answer does not count.
    fn give_back_signature(&mut self, token: &str) {
        if let Some(ticket) = self.tickets.get_mut(token) {
            ticket.left = ticket.left.saturating_add(1).min(SIGNATURES_PER_CHAT);
        }
    }

    /// A reply without an `id` has no signature to fetch, so it gets no ticket.
    fn issue_ticket(&mut self, token: &str, reply_id: Option<String>, now: Instant) {
        let Some(reply_id) = reply_id else {
            return;
        };
        if self.tickets.len() >= MAX_TRACKED {
            self.tickets.retain(|_, ticket| now.duration_since(ticket.issued) < TICKET_LIFETIME);
        }
        if self.tickets.len() < MAX_TRACKED {
            self.tickets.insert(token.to_string(), Ticket { reply_id, left: SIGNATURES_PER_CHAT, issued: now });
        }
    }
}

fn refuse(status: u16, message: &str) -> (u16, Vec<u8>) {
    (status, json!({"error": message}).to_string().into_bytes())
}

fn safe_target(target: &str) -> bool {
    !target.contains("..") && target.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./?=&:".contains(&b))
}

/// The client's own `Accept-Encoding` is dropped and `identity` asked for instead: a compressed
/// reply could not be read here, so it would be withheld after being billed and the token lost.
fn filtered_headers(request: &Request, is_chat: bool) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if is_chat {
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
        headers.extend(
            FORWARDED_HEADERS
                .iter()
                .filter_map(|name| request.header(name).map(|value| (name.to_string(), value.to_string()))),
        );
    }
    headers.push(("Accept-Encoding".to_string(), "identity".to_string()));
    headers
}

/// `x-no-aliasing` is passed on as the client wrote it. Its meaning at NEAR AI is not verified here,
/// so only a short plain word is accepted.
fn plain_word(value: Option<&str>) -> bool {
    value.is_none_or(|v| !v.is_empty() && v.len() <= 16 && v.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn signature_id(target: &str) -> Option<&str> {
    target.strip_prefix("/v1/signature/").and_then(|rest| rest.strip_suffix("?signing_algo=ed25519"))
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_signature_target(target: &str) -> bool {
    signature_id(target).is_some_and(|id| {
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

/// The content must be lowercase hexadecimal, as both the Rust client (`ona-core` `e2ee.rs`,
/// `{:02x}`) and the Python test script (`bytes.hex()`) write it. Anything else is refused.
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
        && request.header("X-Encryption-Version").is_some_and(|v| ENCRYPTION_VERSIONS.contains(&v))
        && is_key_hex(request.header("X-Client-Pub-Key"))
        && is_key_hex(request.header("X-Model-Pub-Key"))
        && plain_word(request.header("x-no-aliasing"));
    if complete {
        Ok(())
    } else {
        Err(refuse(400, "encryption headers are missing or invalid"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    Chat,
    Attestation,
    /// With the id of the reply whose signature is asked for.
    Signature(String),
}

/// What is left to do once a call has been accepted.
pub struct Forward {
    route: Route,
    /// The request token this call shows: spent by a chat, only shown for an attestation, and for a
    /// signature the token of the paid chat.
    token: String,
    headers: Vec<(String, String)>,
}

impl Forward {
    pub(crate) fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
}

/// A call that passed every check needing no relay state. Its request token, if any, is valid but
/// not spent yet.
pub struct CheckedCall(Forward);

impl Verifier {
    /// Most tokens a chat may consume before its reply is withheld: the reply's `max_tokens`, the
    /// largest prompt allowed at one token per byte, and the chat template.
    pub fn reply_limit(&self) -> u64 {
        u64::from(self.config.max_tokens_per_request)
            .saturating_add(u64::try_from(self.config.max_prompt_bytes).unwrap_or(u64::MAX))
            .saturating_add(TEMPLATE_TOKENS)
    }

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
        // The relay pays for the prompt too. At one token per byte at worst (an assumption about the
        // tokenizer, not measured here), a prompt of `max_prompt_bytes` costs at most that many tokens,
        // which `reply_limit` counts.
        let message_bytes = value["messages"][0]["content"].as_str().map_or(0, str::len) / 2;
        if message_bytes > self.config.max_prompt_bytes.saturating_add(ENCRYPTION_OVERHEAD) {
            return Err(refuse(413, "message too long for the request budget"));
        }
        check_encryption_headers(request)
    }

    fn shown_token(&self, request: &Request) -> Result<String, (u16, Vec<u8>)> {
        let Some(encoded) = request.header("X-Ona-Token") else {
            return Err(refuse(401, "missing request token"));
        };
        self.verify_request_token(encoded).map_err(|(status, body)| (status, body.to_string().into_bytes()))
    }

    /// Target, policy and request token signature. Needs no relay state, so it runs unlocked.
    pub fn check_call(&self, policy: &GatewayPolicy, request: &Request) -> Result<CheckedCall, (u16, Vec<u8>)> {
        if !safe_target(&request.target) {
            return Err(refuse(400, "invalid target"));
        }
        let route = if request.method == "POST" && request.target == "/v1/chat/completions" {
            self.check_chat_policy(policy, request)?;
            Route::Chat
        } else if request.method == "GET" && valid_attestation_target(policy, &request.target) {
            Route::Attestation
        } else if request.method == "GET" && valid_signature_target(&request.target) {
            Route::Signature(signature_id(&request.target).unwrap_or_default().to_string())
        } else {
            return Err(refuse(404, "not found"));
        };
        let token = self.shown_token(request)?;
        let headers = filtered_headers(request, route == Route::Chat);
        Ok(CheckedCall(Forward { route, token, headers }))
    }
}

impl<S: Store, C: Chain, U: Upstream> Relay<S, C, U> {
    /// The part of a call's admission that needs the relay state. A chat spends its token, after
    /// every check so that a malformed request does not cost the user anything. An attestation needs
    /// an unused token and counts against it and the global limit. A signature needs a paid chat's
    /// ticket, and nothing else.
    pub fn admit(&mut self, policy: &GatewayPolicy, checked: CheckedCall) -> Result<Forward, (u16, Vec<u8>)> {
        let CheckedCall(forward) = checked;
        let now = Instant::now();
        match &forward.route {
            Route::Chat => self
                .spend_request_token(&forward.token)
                .map_err(|(status, body)| (status, body.to_string().into_bytes()))?,
            Route::Attestation => {
                if self.store.is_request_token_used(&forward.token) {
                    return Err(refuse(409, "request token already used"));
                }
                self.free_routes.admit_attestation(&forward.token, now, policy.free_routes_per_minute)?;
            }
            Route::Signature(id) => self.free_routes.admit_signature(&forward.token, id, now)?,
        }
        Ok(forward)
    }

    /// First half of a call, before the service is contacted.
    pub fn gateway_begin(&mut self, policy: &GatewayPolicy, request: &Request) -> Result<Forward, (u16, Vec<u8>)> {
        let checked = self.verifier.check_call(policy, request)?;
        self.admit(policy, checked)
    }

    /// A chat's request token comes back only when the failure proves the call was not billed.
    fn release_token(&mut self, forward: &Forward) {
        if forward.route == Route::Chat {
            if let Err(e) = self.store.release_request_token(&forward.token) {
                eprintln!("request token not returned: {e}");
            }
        }
    }

    /// Second half of a call, with what the service answered. A signature fetch the service did not
    /// answer with 200 does not use up one of the chat's fetches.
    pub fn gateway_end(&mut self, forward: Forward, outcome: Result<(u16, Vec<u8>), BackendFailure>) -> (u16, Vec<u8>) {
        let answered = matches!(outcome, Ok((200, _)));
        if !answered && matches!(forward.route, Route::Signature(_)) {
            self.free_routes.give_back_signature(&forward.token);
        }
        // A chat's token stays spent unless the call was certainly not billed; only a token that stays
        // spent loses its attestation count, so a returned token keeps the count it had.
        let returned = matches!(outcome, Err(BackendFailure::ConnectionRefused) | Ok((401 | 402 | 429, _)));
        if forward.route == Route::Chat && !returned {
            self.free_routes.token_spent(&forward.token);
        }
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
        if forward.route == Route::Chat {
            let parsed = serde_json::from_slice::<Value>(&reply).ok();
            let used = parsed.as_ref().and_then(|v| v["usage"]["total_tokens"].as_u64());
            // Last resort, paid for already: the count covers the prompt too.
            if used.is_none_or(|n| n > self.verifier.reply_limit()) {
                return refuse(402, "reply withheld: over the request budget");
            }
            let reply_id = parsed.as_ref().and_then(|v| v["id"].as_str()).map(String::from);
            self.free_routes.issue_ticket(&forward.token, reply_id, Instant::now());
        }
        (status, reply)
    }

    /// Handles one call for NEAR AI, single-threaded. A chat spends its request token; an attestation
    /// needs an unused one, which it does not spend; a signature needs the token of the chat it signs.
    /// See `SharedRelay::gateway` for the version used by the relay's threads.
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
