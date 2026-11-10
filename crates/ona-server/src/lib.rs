//! `ona-server`: the relay. It exchanges an on-chain credit for anonymous request tokens, and
//! serves model calls against those tokens. The model and the chain are behind traits and are
//! faked in this version: every model reply is labelled `mode: mock`.
//!
//! Not done yet: fixed-size batches padded with the relay's own tokens, the real RPC client, Tor,
//! and the enclave.

pub mod http;
pub mod mock;
pub mod near;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use ona_token::{
    claim_digest, hash_to_g1, sign_blinded, verify, verify_digest, verify_token, SecretKey, Token,
    G1_LEN, G2_LEN,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const MODE: &str = "mock";
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
pub const MAX_BATCH: usize = 32;
const REQUEST_TOKEN_LEN: usize = 32 + G1_LEN;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn request_dst(relay: &str) -> Vec<u8> {
    format!("ONA-RELAY-V1:{relay}:BLS12381G1_XMD:SHA-256_SSWU_RO_").into_bytes()
}

/// Where a credit stands. Written durably before each step that cannot be undone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeState {
    Pending { blinded_hash: String, token: String, owner_sig: String, blinded: Vec<String> },
    /// Sent to the chain. After a crash, only the chain can say what happened.
    Submitted { blinded_hash: String, token: String, owner_sig: String, blinded: Vec<String> },
    Done { blinded_hash: String, signatures: Vec<String> },
    Refused,
}

pub trait Store {
    fn get(&self, nf: &str) -> Option<ExchangeState>;
    fn put(&mut self, nf: &str, state: ExchangeState) -> Result<(), String>;
    fn unfinished(&self) -> Vec<(String, ExchangeState)>;
    /// Records a request token. Returns false if it was already used.
    fn use_request_token(&mut self, x: &str) -> Result<bool, String>;
}

#[derive(Default)]
pub struct MemoryStore {
    exchanges: BTreeMap<String, ExchangeState>,
    used: BTreeSet<String>,
}

impl Store for MemoryStore {
    fn get(&self, nf: &str) -> Option<ExchangeState> {
        self.exchanges.get(nf).cloned()
    }
    fn put(&mut self, nf: &str, state: ExchangeState) -> Result<(), String> {
        self.exchanges.insert(nf.to_string(), state);
        Ok(())
    }
    fn unfinished(&self) -> Vec<(String, ExchangeState)> {
        self.exchanges
            .iter()
            .filter(|(_, s)| matches!(s, ExchangeState::Pending { .. } | ExchangeState::Submitted { .. }))
            .map(|(k, s)| (k.clone(), s.clone()))
            .collect()
    }
    fn use_request_token(&mut self, x: &str) -> Result<bool, String> {
        Ok(self.used.insert(x.to_string()))
    }
}

fn state_to_json(state: &ExchangeState) -> Value {
    match state {
        ExchangeState::Pending { blinded_hash, token, owner_sig, blinded } => {
            json!({"s":"pending","h":blinded_hash,"t":token,"o":owner_sig,"b":blinded})
        }
        ExchangeState::Submitted { blinded_hash, token, owner_sig, blinded } => {
            json!({"s":"submitted","h":blinded_hash,"t":token,"o":owner_sig,"b":blinded})
        }
        ExchangeState::Done { blinded_hash, signatures } => {
            json!({"s":"done","h":blinded_hash,"g":signatures})
        }
        ExchangeState::Refused => json!({"s":"refused"}),
    }
}

fn state_from_json(v: &Value) -> Option<ExchangeState> {
    let text = |k: &str| v[k].as_str().map(String::from);
    let list = |k: &str| -> Option<Vec<String>> {
        v[k].as_array()?.iter().map(|x| x.as_str().map(String::from)).collect()
    };
    match v["s"].as_str()? {
        "pending" => Some(ExchangeState::Pending { blinded_hash: text("h")?, token: text("t")?, owner_sig: text("o")?, blinded: list("b")? }),
        "submitted" => Some(ExchangeState::Submitted { blinded_hash: text("h")?, token: text("t")?, owner_sig: text("o")?, blinded: list("b")? }),
        "done" => Some(ExchangeState::Done { blinded_hash: text("h")?, signatures: list("g")? }),
        "refused" => Some(ExchangeState::Refused),
        _ => None,
    }
}

/// Append-only log, synced to disk on every write. The latest line for a key wins.
pub struct FileStore {
    file: File,
    memory: MemoryStore,
}

impl FileStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut memory = MemoryStore::default();
        if path.exists() {
            let reader = BufReader::new(File::open(path).map_err(|e| e.to_string())?);
            for line in reader.lines() {
                let line = line.map_err(|e| e.to_string())?;
                let v: Value = serde_json::from_str(&line).map_err(|_| "corrupt store line".to_string())?;
                if let Some(x) = v["x"].as_str() {
                    memory.used.insert(x.to_string());
                } else {
                    let nf = v["nf"].as_str().ok_or("corrupt store line")?;
                    let state = state_from_json(&v["state"]).ok_or("corrupt store line")?;
                    memory.exchanges.insert(nf.to_string(), state);
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path).map_err(|e| e.to_string())?;
        Ok(Self { file, memory })
    }

    fn write_line(&mut self, line: &Value) -> Result<(), String> {
        writeln!(self.file, "{line}").map_err(|e| e.to_string())?;
        self.file.sync_all().map_err(|e| e.to_string())
    }
}

impl Store for FileStore {
    fn get(&self, nf: &str) -> Option<ExchangeState> {
        self.memory.get(nf)
    }
    fn put(&mut self, nf: &str, state: ExchangeState) -> Result<(), String> {
        self.write_line(&json!({"nf": nf, "state": state_to_json(&state)}))?;
        self.memory.put(nf, state)
    }
    fn unfinished(&self) -> Vec<(String, ExchangeState)> {
        self.memory.unfinished()
    }
    fn use_request_token(&mut self, x: &str) -> Result<bool, String> {
        if self.memory.used.contains(x) {
            return Ok(false);
        }
        self.write_line(&json!({"x": x}))?;
        self.memory.use_request_token(x)
    }
}

pub struct Claim {
    pub token: Token,
    pub owner_sig: [u8; 64],
}

pub trait Chain {
    /// Must read a final block.
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String>;
    /// Sends `relay_claim` and waits for finality. One result per item.
    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String>;
    /// Whether this relay's own claim of the nullifier reached the chain, for crash recovery.
    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String>;
}

pub struct ModelReply {
    pub text: String,
    pub tokens_used: u32,
}

pub trait Upstream {
    fn complete(&mut self, prompt: &str, max_tokens: u32) -> Result<ModelReply, String>;
}

pub struct Config {
    pub mint: String,
    pub relay: String,
    pub mint_dst: Vec<u8>,
    pub credit_key: [u8; G2_LEN],
    /// Request tokens given for one credit.
    pub tokens_per_credit: usize,
    /// Most model tokens a single request may consume.
    pub max_tokens_per_request: u32,
}

pub struct Relay<S, C, U> {
    pub store: S,
    pub chain: C,
    pub upstream: U,
    config: Config,
    request_key: SecretKey,
    request_pk: [u8; G2_LEN],
    dst: Vec<u8>,
}

pub type Response = (u16, Value);

fn error(status: u16, message: &str) -> Response {
    (status, json!({"error": message, "mode": MODE}))
}

fn hash_blinded(blinded: &[String]) -> String {
    let mut h = Sha256::new();
    for b in blinded {
        h.update(b.as_bytes());
        h.update([0]);
    }
    to_hex(&h.finalize())
}

impl<S: Store, C: Chain, U: Upstream> Relay<S, C, U> {
    pub fn new(store: S, chain: C, upstream: U, config: Config, request_key: SecretKey) -> Self {
        let request_pk = request_key.public_key();
        let dst = request_dst(&config.relay);
        Self { store, chain, upstream, config, request_key, request_pk, dst }
    }

    pub fn request_public_key(&self) -> [u8; G2_LEN] {
        self.request_pk
    }

    pub fn request_dst(&self) -> &[u8] {
        &self.dst
    }

    fn parse_exchange(&self, body: &Value) -> Result<(Token, [u8; 64], Vec<String>), Response> {
        let bad = || error(400, "malformed exchange request");
        let token_bytes = body["token"].as_str().and_then(from_hex).ok_or_else(bad)?;
        let token = Token::from_bytes(&token_bytes).map_err(|_| bad())?;
        let sig: [u8; 64] = body["owner_sig"]
            .as_str()
            .and_then(from_hex)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(bad)?;
        let blinded: Vec<String> = body["blinded"]
            .as_array()
            .ok_or_else(bad)?
            .iter()
            .map(|b| b.as_str().map(String::from))
            .collect::<Option<_>>()
            .ok_or_else(bad)?;
        if blinded.len() != self.config.tokens_per_credit {
            return Err(error(400, "wrong number of blinded points"));
        }
        for b in &blinded {
            let bytes = from_hex(b).ok_or_else(bad)?;
            let point: [u8; G1_LEN] = bytes.try_into().map_err(|_| bad())?;
            // Refused now: otherwise the credit would be claimed and then fail at signing time.
            sign_blinded(&self.request_key, &point).map_err(|_| error(400, "invalid blinded point"))?;
        }
        Ok((token, sig, blinded))
    }

    fn exchange_reply(state: &ExchangeState, blinded_hash: &str) -> Response {
        match state {
            ExchangeState::Pending { blinded_hash: h, .. } | ExchangeState::Submitted { blinded_hash: h, .. } => {
                if h == blinded_hash {
                    (202, json!({"state": "pending", "mode": MODE}))
                } else {
                    error(409, "credit already used with other blinded points")
                }
            }
            ExchangeState::Done { blinded_hash: h, signatures } => {
                if h == blinded_hash {
                    (200, json!({"state": "done", "signatures": signatures, "mode": MODE}))
                } else {
                    error(409, "credit already used with other blinded points")
                }
            }
            ExchangeState::Refused => error(409, "credit refused"),
        }
    }

    /// Accepts a credit for the next batch. Nothing is signed until the chain has confirmed the
    /// claim. The same request can be repeated safely to collect the result.
    pub fn exchange(&mut self, body: &Value) -> Response {
        let (token, owner_sig, blinded) = match self.parse_exchange(body) {
            Ok(parsed) => parsed,
            Err(response) => return response,
        };
        let blinded_hash = hash_blinded(&blinded);
        let nf = token.nullifier();
        let key = to_hex(&nf);
        if let Some(existing) = self.store.get(&key) {
            return Self::exchange_reply(&existing, &blinded_hash);
        }
        if token.denom_id != 0 {
            return error(400, "only the lowest tier buys request tokens");
        }
        if !verify_token(&self.config.credit_key, &token, &self.config.mint_dst) {
            return error(400, "invalid token");
        }
        let digest = claim_digest(&self.config.mint, &self.config.relay, &nf);
        if !verify_digest(&token.pk, &digest, &owner_sig) {
            return error(400, "invalid owner signature");
        }
        match self.chain.is_spent(&nf) {
            Ok(false) => {}
            Ok(true) => return error(409, "credit already spent"),
            Err(_) => return error(503, "chain unavailable"),
        }
        let state = ExchangeState::Pending {
            blinded_hash: blinded_hash.clone(),
            token: to_hex(&token.to_bytes()),
            owner_sig: to_hex(&owner_sig),
            blinded,
        };
        if self.store.put(&key, state.clone()).is_err() {
            return error(503, "storage unavailable");
        }
        Self::exchange_reply(&state, &blinded_hash)
    }

    fn sign_all(&self, blinded: &[String]) -> Result<Vec<String>, String> {
        blinded
            .iter()
            .map(|b| {
                let bytes = from_hex(b).ok_or("stored point is not hex")?;
                let point: [u8; G1_LEN] = bytes.try_into().map_err(|_| "stored point length")?;
                sign_blinded(&self.request_key, &point).map(|s| to_hex(&s)).map_err(|e| e.to_string())
            })
            .collect()
    }

    fn finish(&mut self, nf: &str, blinded_hash: String, blinded: &[String], accepted: bool) -> Result<(), String> {
        let state = if accepted {
            ExchangeState::Done { blinded_hash, signatures: self.sign_all(blinded)? }
        } else {
            ExchangeState::Refused
        };
        self.store.put(nf, state)
    }

    /// Settles records left in `Submitted` by a crash. The chain decides, never the local state.
    pub fn recover(&mut self) -> Result<usize, String> {
        let mut settled = 0;
        for (nf, state) in self.store.unfinished() {
            if let ExchangeState::Submitted { blinded_hash, blinded, .. } = state {
                let raw: [u8; 32] = from_hex(&nf)
                    .and_then(|v| v.try_into().ok())
                    .ok_or("stored nullifier is not valid")?;
                if self.chain.claimed_by_relay(&raw)? {
                    self.finish(&nf, blinded_hash, &blinded, true)?;
                    settled += 1;
                } else if self.chain.is_spent(&raw)? {
                    self.finish(&nf, blinded_hash, &blinded, false)?;
                    settled += 1;
                }
                // Neither claimed nor spent: the transaction never landed. `flush` resends it.
            }
        }
        Ok(settled)
    }

    /// Sends one batch of credits to the chain. Signs only those the chain accepted.
    pub fn flush(&mut self) -> Result<usize, String> {
        // A claim that landed but whose reply was lost would come back `false` if sent again,
        // and the user would lose a credit the relay really collected.
        self.recover()?;
        let batch: Vec<(String, ExchangeState)> = self.store.unfinished().into_iter().take(MAX_BATCH).collect();
        if batch.is_empty() {
            return Ok(0);
        }
        let mut claims = Vec::with_capacity(batch.len());
        let mut parts = Vec::with_capacity(batch.len());
        for (nf, state) in batch {
            let (ExchangeState::Pending { blinded_hash, token, owner_sig, blinded }
            | ExchangeState::Submitted { blinded_hash, token, owner_sig, blinded }) = state
            else {
                continue;
            };
            let token_bytes = from_hex(&token).ok_or("stored token is not hex")?;
            let parsed = Token::from_bytes(&token_bytes).map_err(|e| e.to_string())?;
            let sig: [u8; 64] = from_hex(&owner_sig)
                .and_then(|v| v.try_into().ok())
                .ok_or("stored signature is not valid")?;
            self.store.put(
                &nf,
                ExchangeState::Submitted {
                    blinded_hash: blinded_hash.clone(),
                    token,
                    owner_sig,
                    blinded: blinded.clone(),
                },
            )?;
            claims.push(Claim { token: parsed, owner_sig: sig });
            parts.push((nf, blinded_hash, blinded));
        }
        let results = self.chain.relay_claim(&claims)?;
        if results.len() != claims.len() {
            return Err("chain returned the wrong number of results".into());
        }
        let mut accepted = 0;
        for ((nf, blinded_hash, blinded), ok) in parts.into_iter().zip(results) {
            self.finish(&nf, blinded_hash, &blinded, ok)?;
            accepted += usize::from(ok);
        }
        Ok(accepted)
    }

    fn check_request_token(&mut self, encoded: &str) -> Result<String, Response> {
        let bytes = from_hex(encoded).filter(|b| b.len() == REQUEST_TOKEN_LEN).ok_or_else(|| error(400, "malformed request token"))?;
        let (x, sig) = bytes.split_at(32);
        let sig: [u8; G1_LEN] = sig.try_into().map_err(|_| error(400, "malformed request token"))?;
        if !verify(&self.request_pk, x, &self.dst, &sig) {
            return Err(error(401, "invalid request token"));
        }
        let id = to_hex(x);
        // Written before the model call, so a crash cannot make a token reusable.
        match self.store.use_request_token(&id) {
            Ok(true) => Ok(id),
            Ok(false) => Err(error(409, "request token already used")),
            Err(_) => Err(error(503, "storage unavailable")),
        }
    }

    /// Serves one model call. The token is spent even if the model fails: the budget is checked
    /// on what the model actually consumed, and a reply over budget is withheld.
    pub fn chat(&mut self, body: &Value) -> Response {
        let Some(token) = body["token"].as_str() else {
            return error(400, "missing request token");
        };
        let Some(prompt) = body["prompt"].as_str() else {
            return error(400, "missing prompt");
        };
        if prompt.len() > MAX_PROMPT_BYTES {
            return error(413, "prompt too long");
        }
        if let Err(response) = self.check_request_token(token) {
            return response;
        }
        let max = self.config.max_tokens_per_request;
        match self.upstream.complete(prompt, max) {
            Ok(reply) if reply.tokens_used > max => error(402, "reply withheld: over the request budget"),
            Ok(reply) => (200, json!({"reply": reply.text, "tokens_used": reply.tokens_used, "mode": MODE})),
            Err(_) => error(502, "model unavailable"),
        }
    }

    pub fn handle(&mut self, path: &str, body: &str) -> Response {
        let Ok(value) = serde_json::from_str::<Value>(body) else {
            return error(400, "body is not valid JSON");
        };
        match path {
            "/exchange" => self.exchange(&value),
            "/chat" => self.chat(&value),
            _ => error(404, "not found"),
        }
    }
}

pub fn request_message_point(x: &[u8; 32], dst: &[u8]) -> [u8; G1_LEN] {
    hash_to_g1(x, dst)
}
