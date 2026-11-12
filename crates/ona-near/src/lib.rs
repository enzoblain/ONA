//! A small blocking NEAR RPC client: JSON-RPC calls and hand-encoded, ed25519-signed transactions.
//! Only the actions ONA needs are supported.
//!
//! The RPC node is trusted. A view, a nonce or a block timestamp it returns is never checked against a
//! proof, so a dishonest node can lie about the state of the chain (SPEC.md, "NEAR RPC client"). What this
//! client does refuse is a node that would make it sign something else than what the caller asked for.
#![deny(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const TGAS: u64 = 1_000_000_000_000;
pub const BLOCK_HASH_LEN: usize = 32;
const RPC_TIMEOUT: Duration = Duration::from_secs(120);
/// How many times the fate of a transaction is asked for after an unclear answer to `send_tx`.
const STATUS_CHECKS: u32 = 3;
const STATUS_WAIT: Duration = Duration::from_secs(2);
const MAX_KEY_FILE: u64 = 4096;

pub enum Action {
    Create,
    Deploy(Vec<u8>),
    Call { method: String, args: Vec<u8>, gas: u64, deposit: u128 },
    Transfer(u128),
    AddFullKey([u8; 32]),
}

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s);
}

fn encode_action(out: &mut Vec<u8>, action: &Action) {
    match action {
        Action::Create => out.push(0),
        Action::Deploy(code) => {
            out.push(1);
            put_str(out, code);
        }
        Action::Call { method, args, gas, deposit } => {
            out.push(2);
            put_str(out, method.as_bytes());
            put_str(out, args);
            out.extend_from_slice(&gas.to_le_bytes());
            out.extend_from_slice(&deposit.to_le_bytes());
        }
        Action::Transfer(amount) => {
            out.push(3);
            out.extend_from_slice(&amount.to_le_bytes());
        }
        Action::AddFullKey(pk) => {
            out.push(5);
            out.push(0);
            out.extend_from_slice(pk);
            out.extend_from_slice(&0u64.to_le_bytes());
            out.push(1);
        }
    }
}

/// Borsh encoding of a NEAR `Transaction` (version 0), ready to be hashed and signed.
///
/// The block hash is a fixed 32 bytes: a longer one, inserted as is, would let whoever chose it append
/// actions of its own to the signed bytes.
pub fn encode_transaction(
    signer: &str,
    public_key: &[u8; 32],
    nonce: u64,
    receiver: &str,
    block_hash: &[u8; BLOCK_HASH_LEN],
    actions: &[Action],
) -> Vec<u8> {
    let mut tx = Vec::new();
    put_str(&mut tx, signer.as_bytes());
    tx.push(0);
    tx.extend_from_slice(public_key);
    tx.extend_from_slice(&nonce.to_le_bytes());
    put_str(&mut tx, receiver.as_bytes());
    tx.extend_from_slice(block_hash);
    tx.extend_from_slice(&(actions.len() as u32).to_le_bytes());
    for action in actions {
        encode_action(&mut tx, action);
    }
    tx
}

/// Reads the `block_hash` an RPC node returned: base58 of exactly 32 bytes, nothing else.
pub fn decode_block_hash(value: &Value) -> Result<[u8; BLOCK_HASH_LEN]> {
    let text = value.as_str().ok_or_else(|| anyhow!("the node returned no block hash"))?;
    let bytes = bs58::decode(text).into_vec().context("block hash is not base58")?;
    bytes.try_into().map_err(|b: Vec<u8>| anyhow!("block hash must be {BLOCK_HASH_LEN} bytes, the node returned {}", b.len()))
}

/// Checks the shape of a NEAR account id: 2 to 64 characters among `a-z`, `0-9`, `-`, `_`, `.`, a
/// separator never first, last or next to another. Implicit accounts (64 hexadecimal characters) pass.
pub fn check_account_id(account: &str) -> Result<()> {
    let bytes = account.as_bytes();
    if !(2..=64).contains(&bytes.len()) {
        bail!("account id {account:?} must be 2 to 64 characters long");
    }
    let separator = |c: u8| matches!(c, b'-' | b'_' | b'.');
    let mut previous_separator = true;
    for &c in bytes {
        if separator(c) {
            if previous_separator {
                bail!("account id {account:?} has a misplaced separator");
            }
            previous_separator = true;
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            previous_separator = false;
        } else {
            bail!("account id {account:?} may only hold a-z, 0-9, '-', '_' and '.'");
        }
    }
    if previous_separator {
        bail!("account id {account:?} ends with a separator");
    }
    Ok(())
}

/// An RPC address must use `https`. Plain `http` is only accepted to this machine (`127.0.0.1`,
/// `localhost`, `[::1]`), for a local node. A user name in the address is refused.
pub fn check_rpc_url(url: &str) -> Result<()> {
    check_url(url, false)
}

/// For a client that goes through Tor: as [`check_rpc_url`], and plain `http` to an onion address is also
/// accepted, since Tor encrypts the connection to an onion service end to end.
pub fn check_tor_rpc_url(url: &str) -> Result<()> {
    check_url(url, true)
}

fn check_url(url: &str, onion_http: bool) -> Result<()> {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("RPC URL contains spaces or control characters");
    }
    let lower = url.to_ascii_lowercase();
    let (secure, rest) = if let Some(rest) = lower.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = lower.strip_prefix("http://") {
        (false, rest)
    } else {
        bail!("RPC URL must start with https://");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        bail!("RPC URL must not contain a user name");
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or_else(|| anyhow!("RPC URL has an unclosed IPv6 address"))?;
        (host, after.strip_prefix(':'))
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        bail!("RPC URL has no host");
    }
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            bail!("RPC URL has an invalid port");
        }
    }
    let onion = onion_http && host.len() > ".onion".len() && host.ends_with(".onion");
    if !secure && !onion && !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        bail!("RPC URL must use https (http is only accepted to 127.0.0.1 or localhost)");
    }
    Ok(())
}

/// Compares the chain id a node reports with the one expected. Mainnet is refused, whatever is expected.
pub fn check_chain_id(expected: &str, reported: &str) -> Result<()> {
    if expected.is_empty() || expected.to_ascii_lowercase().contains("mainnet") {
        bail!("expected chain {expected:?} is refused: only testnet and local networks are allowed");
    }
    if reported.is_empty() || reported.to_ascii_lowercase().contains("mainnet") {
        bail!("the node reports chain {reported:?}, refused");
    }
    if reported != expected {
        bail!("expected chain {expected:?} but the node reports {reported:?}");
    }
    Ok(())
}

/// Asks the node for its chain id (`status`) and checks it with [`check_chain_id`]. Call it before
/// sending anything: a node's address or a configured name proves nothing about the network.
pub fn check_network(rpc: &Client, expected_chain_id: &str) -> Result<String> {
    if expected_chain_id.is_empty() || expected_chain_id.to_ascii_lowercase().contains("mainnet") {
        bail!("expected chain {expected_chain_id:?} is refused: only testnet and local networks are allowed");
    }
    let status = rpc.post("status", json!([]))?;
    let reported = status["chain_id"].as_str().unwrap_or_default();
    check_chain_id(expected_chain_id, reported)?;
    Ok(reported.to_string())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no argument, cannot fail and touches no memory of ours.
    unsafe { libc::geteuid() }
}

/// Reads a NEAR account key (`ed25519:<base58>`). The file is opened once, without following a symbolic
/// link, and must be a regular file that belongs to the current user and that only they can read.
#[cfg(unix)]
pub fn load_account_key(path: &Path) -> Result<SigningKey> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("cannot read account key (a symbolic link is refused)")?;
    let meta = file.metadata().context("cannot read account key")?;
    if !meta.file_type().is_file() {
        bail!("account key must be a regular file");
    }
    if meta.permissions().mode() & 0o077 != 0 {
        bail!("account key file is accessible to other users");
    }
    if meta.uid() != effective_uid() {
        bail!("account key file belongs to another user");
    }
    if meta.len() > MAX_KEY_FILE {
        bail!("account key file is too large");
    }
    let mut text = Zeroizing::new(String::new());
    file.by_ref().take(MAX_KEY_FILE).read_to_string(&mut text).context("cannot read account key")?;
    parse_account_key(text.trim())
}

/// Not on this system: the owner and permission checks above have no equivalent here yet, so no key file is
/// read rather than one read without them.
#[cfg(not(unix))]
pub fn load_account_key(_path: &Path) -> Result<SigningKey> {
    bail!("reading a NEAR account key file is only supported on macOS and Linux")
}

/// Accepts the 64-byte form NEAR tools write, and refuses one whose public half does not match.
pub fn parse_account_key(text: &str) -> Result<SigningKey> {
    let encoded = text.strip_prefix("ed25519:").ok_or_else(|| anyhow!("account key must start with ed25519:"))?;
    let bytes = Zeroizing::new(bs58::decode(encoded).into_vec().context("account key is not base58")?);
    if bytes.len() != 64 {
        bail!("account key must be 64 bytes");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes[..32]);
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key().as_bytes()[..] != bytes[32..] {
        bail!("account key is inconsistent");
    }
    Ok(key)
}

/// The result of a transaction once all its receipts have run.
///
/// Two different things can fail. `failure` is the status of the transaction itself: the chain of promises
/// its first receipt returned. `failed_receipts` lists every receipt that failed, including those the
/// contract handled itself in a callback (a refund after a failed payment, a placement undone) and those of
/// promises it did not wait for. A caller that needs every effect to have happened uses
/// [`Outcome::require_all_receipts_ok`]; a caller that relies on the contract's own handling of a failed
/// sub-call reads `failure` and then the contract's state.
pub struct Outcome {
    pub tgas: f64,
    /// Set when the transaction's own status is a failure.
    pub failure: Option<String>,
    pub value: Value,
    /// Every failed receipt the node reported, in order, whatever the transaction's own status.
    pub failed_receipts: Vec<String>,
    /// The hash the chain knows the transaction by (SHA-256 of the unsigned transaction). Set by
    /// [`Client::send`] and [`Client::tx_status`].
    pub tx_hash: Option<[u8; 32]>,
}

impl Outcome {
    /// Succeeds only when the transaction succeeded and no receipt failed.
    pub fn require_all_receipts_ok(&self) -> Result<()> {
        if let Some(failure) = &self.failure {
            bail!("the transaction failed: {failure}");
        }
        if let Some(first) = self.failed_receipts.first() {
            bail!("{} receipt(s) failed, first {first}", self.failed_receipts.len());
        }
        Ok(())
    }
}

/// Reads a `send_tx` or `tx` result. The node must state that the result is `FINAL` and give the list of
/// receipts; the status must be `SuccessValue` or `Failure`. Anything else is an error, never an assumed
/// success or failure.
pub fn parse_outcome(result: &Value) -> Result<Outcome> {
    match result.get("final_execution_status") {
        Some(level) if level == "FINAL" => {}
        Some(level) => bail!("the transaction is not final yet ({level})"),
        None => bail!("the node did not say whether the result is final"),
    }
    if !result["receipts_outcome"].is_array() {
        bail!("the node gave no list of receipts");
    }
    let mut burnt = result["transaction_outcome"]["outcome"]["gas_burnt"].as_u64().unwrap_or(0);
    let mut failed_receipts = Vec::new();
    if let Some(failure) = result["transaction_outcome"]["outcome"]["status"].get("Failure") {
        failed_receipts.push(format!("transaction: {failure}"));
    }
    for receipt in result["receipts_outcome"].as_array().into_iter().flatten() {
        burnt = burnt.saturating_add(receipt["outcome"]["gas_burnt"].as_u64().unwrap_or(0));
        if let Some(failure) = receipt["outcome"]["status"].get("Failure") {
            failed_receipts.push(format!("receipt {}: {failure}", receipt["id"].as_str().unwrap_or("?")));
        }
    }
    let tgas = burnt as f64 / TGAS as f64;
    let status = &result["status"];
    if let Some(failure) = status.get("Failure") {
        return Ok(Outcome { tgas, failure: Some(failure.to_string()), value: Value::Null, failed_receipts, tx_hash: None });
    }
    let encoded = status
        .get("SuccessValue")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("transaction has no final status: {status}"))?;
    let decoded = B64.decode(encoded).context("SuccessValue is not base64")?;
    // An empty or non-JSON value is still a success: methods returning nothing produce "".
    let value = serde_json::from_slice(&decoded).unwrap_or(Value::Null);
    Ok(Outcome { tgas, failure: None, value, failed_receipts, tx_hash: None })
}

/// A transaction signed and not sent yet ([`Client::sign_tx`]).
pub struct SignedTx {
    /// The hash the chain will know it by.
    pub hash: [u8; 32],
    signer: String,
    bytes: Vec<u8>,
}

/// `send_tx` gave no clear answer and the node could not say what became of the transaction. It may
/// still be included until its block hash expires. Ask [`Client::tx_status`] before sending anything that
/// would repeat it.
#[derive(Debug)]
pub struct TxUnknown {
    pub hash: [u8; 32],
    pub signer: String,
    pub cause: String,
}

impl fmt::Display for TxUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "transaction {} from {}: outcome unknown ({}). It may still be included: check its status before sending it again",
            bs58::encode(self.hash).into_string(),
            self.signer,
            self.cause
        )
    }
}

impl std::error::Error for TxUnknown {}

enum RpcFailure {
    /// Nothing was sent.
    NotSent(String),
    /// Something was sent, but no usable answer came back: whether the node acted is unknown.
    Unclear(String),
    /// The node answered with a JSON-RPC error.
    Error(Value),
}

impl RpcFailure {
    fn into_error(self) -> anyhow::Error {
        match self {
            RpcFailure::NotSent(m) => anyhow!("RPC request not sent: {m}"),
            RpcFailure::Unclear(m) => anyhow!("RPC request failed: {m}"),
            RpcFailure::Error(err) => anyhow!("rpc error: {err}"),
        }
    }
}

fn error_names(err: &Value) -> [&str; 2] {
    [err["name"].as_str().unwrap_or_default(), err["cause"]["name"].as_str().unwrap_or_default()]
}

/// The node checked the transaction and refused it, so it will not run. These names come from the NEAR RPC
/// documentation and were not checked against a node.
fn is_definite_rejection(err: &Value) -> bool {
    error_names(err).iter().any(|n| matches!(*n, "INVALID_TRANSACTION" | "PARSE_ERROR" | "REQUEST_VALIDATION_ERROR"))
}

fn is_unknown_transaction(err: &Value) -> bool {
    error_names(err).contains(&"UNKNOWN_TRANSACTION")
}

/// A transaction result names its own hash: a node that answers for another transaction is refused.
fn check_result_hash(result: &Value, hash: &[u8; 32]) -> Result<()> {
    if let Some(reported) = result["transaction"]["hash"].as_str() {
        if reported != bs58::encode(hash).into_string() {
            bail!("the node answered for transaction {reported}, not for the one sent");
        }
    }
    Ok(())
}

pub struct Client {
    url: String,
    agent: ureq::Agent,
    key: SigningKey,
    status_checks: u32,
    status_wait: Duration,
    /// Set for a client whose agent sends everything through Tor: plain http to an onion address is then
    /// accepted ([`check_tor_rpc_url`]).
    through_tor: bool,
}

impl Client {
    /// Redirects are not followed and proxy variables of the environment are ignored: either could send
    /// the requests somewhere else than `url`. The address itself is checked by [`check_rpc_url`] before
    /// each request; [`Client::connect`] checks it at once.
    pub fn new(url: &str, key: SigningKey) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(RPC_TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .build()
            .into();
        Self { url: url.to_string(), agent, key, status_checks: STATUS_CHECKS, status_wait: STATUS_WAIT, through_tor: false }
    }

    /// Like [`Client::new`], but refuses a bad address immediately.
    pub fn connect(url: &str, key: SigningKey) -> Result<Self> {
        check_rpc_url(url)?;
        Ok(Self::new(url, key))
    }

    /// Uses a caller-built agent that sends everything through Tor (`ona_tor::near_client`). Its address is
    /// checked by [`check_tor_rpc_url`]. The caller is responsible for the agent's redirect and proxy settings.
    pub fn with_agent(url: &str, key: SigningKey, agent: ureq::Agent) -> Self {
        Self { url: url.to_string(), agent, key, status_checks: STATUS_CHECKS, status_wait: STATUS_WAIT, through_tor: true }
    }

    fn check_url(&self) -> Result<()> {
        if self.through_tor {
            check_tor_rpc_url(&self.url)
        } else {
            check_rpc_url(&self.url)
        }
    }

    /// How many times, and how far apart, the fate of a transaction is asked for after an unclear answer.
    pub fn with_status_checks(mut self, checks: u32, wait: Duration) -> Self {
        self.status_checks = checks;
        self.status_wait = wait;
        self
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn post_raw(&self, method: &str, params: Value) -> Result<Value, RpcFailure> {
        self.check_url().map_err(|e| RpcFailure::NotSent(e.to_string()))?;
        let body = json!({"jsonrpc":"2.0","id":"1","method":method,"params":params}).to_string();
        let mut response = match self.agent.post(&self.url).header("Content-Type", "application/json").send(body) {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(code)) => return Err(RpcFailure::Unclear(format!("HTTP status {code}"))),
            Err(e) => return Err(RpcFailure::Unclear(e.to_string())),
        };
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().map_err(|e| RpcFailure::Unclear(format!("cannot read the response: {e}")))?;
        let value: Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => {
                let start: String = text.chars().take(200).collect();
                return Err(RpcFailure::Unclear(format!("HTTP status {status}, not JSON: {start}")));
            }
        };
        if let Some(err) = value.get("error") {
            return Err(RpcFailure::Error(err.clone()));
        }
        if status != 200 {
            return Err(RpcFailure::Unclear(format!("HTTP status {status}")));
        }
        value.get("result").cloned().ok_or_else(|| RpcFailure::Unclear("the response has no result".into()))
    }

    pub fn post(&self, method: &str, params: Value) -> Result<Value> {
        self.post_raw(method, params).map_err(RpcFailure::into_error)
    }

    pub fn query(&self, params: Value) -> Result<Value> {
        self.post("query", params)
    }

    fn view_at(&self, finality: &str, account: &str, method: &str, args: Value) -> Result<Value> {
        let result = self.query(json!({
            "request_type":"call_function","finality":finality,"account_id":account,
            "method_name":method,"args_base64":B64.encode(args.to_string()),
        }))?;
        let bytes: Vec<u8> = result["result"]
            .as_array()
            .ok_or_else(|| anyhow!("view failed: {result}"))?
            .iter()
            .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()).ok_or_else(|| anyhow!("view result is not a list of bytes")))
            .collect::<Result<_>>()?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn view(&self, account: &str, method: &str, args: Value) -> Result<Value> {
        self.view_at("optimistic", account, method, args)
    }

    /// A view on a final block. Use it for anything a signature or a payment depends on.
    pub fn view_final(&self, account: &str, method: &str, args: Value) -> Result<Value> {
        self.view_at("final", account, method, args)
    }

    /// The account as the latest final block sees it (`view_account`), or `None` if it does not exist.
    pub fn account(&self, account: &str) -> Result<Option<Value>> {
        match self.query(json!({"request_type":"view_account","finality":"final","account_id":account})) {
            Ok(result) => Ok(Some(result)),
            Err(e) if e.to_string().contains("UNKNOWN_ACCOUNT") => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn balance(&self, account: &str) -> Result<Option<u128>> {
        let params = json!({"request_type":"view_account","finality":"optimistic","account_id":account});
        match self.query(params) {
            Ok(result) => Ok(Some(result["amount"].as_str().unwrap_or("0").parse()?)),
            Err(e) if e.to_string().contains("UNKNOWN_ACCOUNT") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Timestamp of the latest final block, in nanoseconds.
    pub fn final_timestamp(&self) -> Result<u64> {
        let block = self.post("block", json!({"finality":"final"}))?;
        let header = &block["header"];
        header["timestamp_nanosec"]
            .as_str()
            .and_then(|t| t.parse().ok())
            .or_else(|| header["timestamp"].as_u64())
            .ok_or_else(|| anyhow!("block without a timestamp: {block}"))
    }

    /// Signs a transaction: returns the signed bytes and the transaction hash.
    fn sign(&self, signer: &str, receiver: &str, actions: &[Action]) -> Result<(Vec<u8>, [u8; 32])> {
        let public_key = self.public_key();
        let info = self.query(json!({
            "request_type":"view_access_key","finality":"final","account_id":signer,
            "public_key":format!("ed25519:{}", bs58::encode(public_key).into_string()),
        }))?;
        if info.get("error").is_some() {
            bail!("no key for {signer}: {info}");
        }
        let nonce = info["nonce"]
            .as_u64()
            .ok_or_else(|| anyhow!("no nonce: {info}"))?
            .checked_add(1)
            .ok_or_else(|| anyhow!("the access key nonce is exhausted"))?;
        let block_hash = decode_block_hash(&info["block_hash"])?;

        let mut signed = encode_transaction(signer, &public_key, nonce, receiver, &block_hash, actions);
        let hash: [u8; 32] = Sha256::digest(&signed).into();
        let signature = self.key.sign(&hash).to_bytes();
        signed.push(0);
        signed.extend_from_slice(&signature);
        Ok((signed, hash))
    }

    /// Signs and sends a transaction, and waits for its final result. The outcome carries its hash.
    ///
    /// A clear refusal by the node is an error. When the answer is unclear (a timeout, an HTTP error, a
    /// result that is not final), the node is asked what became of the transaction, a few times; if it
    /// still cannot say, the error is a [`TxUnknown`] carrying the hash. The transaction is never sent
    /// twice.
    pub fn send(&self, signer: &str, receiver: &str, actions: Vec<Action>) -> Result<Outcome> {
        let tx = self.sign_tx(signer, receiver, actions)?;
        self.send_signed(&tx)
    }

    /// Signs a transaction without sending it. Its hash, known from here, is the name the chain will know it by:
    /// a caller can record it before [`Client::send_signed`] broadcasts it, so a crash in between loses nothing.
    pub fn sign_tx(&self, signer: &str, receiver: &str, actions: Vec<Action>) -> Result<SignedTx> {
        check_account_id(signer)?;
        check_account_id(receiver)?;
        self.check_url()?;
        let (bytes, hash) = self.sign(signer, receiver, &actions)?;
        Ok(SignedTx { hash, signer: signer.to_string(), bytes })
    }

    /// Sends a transaction signed by [`Client::sign_tx`] and waits for its final result, as [`Client::send`].
    pub fn send_signed(&self, tx: &SignedTx) -> Result<Outcome> {
        let (signed, hash, signer) = (&tx.bytes, tx.hash, tx.signer.as_str());
        let unknown = |cause: String| anyhow::Error::new(TxUnknown { hash, signer: signer.to_string(), cause });

        // `broadcast_tx_commit` only waits for optimistic execution. A signature or a payment must
        // rest on a final result (docs.near.org/api/rpc/transactions, read 2026-11-10).
        let params = json!({"signed_tx_base64": B64.encode(&signed), "wait_until": "FINAL"});
        // Only a final result that names this transaction is an answer. Anything else (another hash, a result
        // that is not final, no receipts) is unclear: the transaction may have run, so its fate is asked for.
        let cause = match self.post_raw("send_tx", params) {
            Ok(result) => match check_result_hash(&result, &hash).and_then(|()| parse_outcome(&result)) {
                Ok(outcome) => return Ok(Outcome { tx_hash: Some(hash), ..outcome }),
                Err(e) => e.to_string(),
            },
            Err(RpcFailure::NotSent(m)) => bail!("transaction not sent: {m}"),
            Err(RpcFailure::Error(err)) if is_definite_rejection(&err) => {
                bail!("transaction {} refused by the node: {err}", bs58::encode(hash).into_string())
            }
            Err(RpcFailure::Error(err)) => format!("rpc error: {err}"),
            Err(RpcFailure::Unclear(m)) => m,
        };
        for attempt in 0..self.status_checks {
            if attempt > 0 {
                std::thread::sleep(self.status_wait);
            }
            if let Ok(Some(outcome)) = self.tx_status(&hash, signer) {
                return Ok(outcome);
            }
        }
        Err(unknown(cause))
    }

    /// What became of a transaction: its final outcome, or `None` while the node does not know it or it
    /// is not final yet. The method and parameters (`tx`, `tx_hash`, `sender_account_id`, `wait_until`) come
    /// from the NEAR RPC documentation and were not checked against a node.
    pub fn tx_status(&self, tx_hash: &[u8; 32], sender: &str) -> Result<Option<Outcome>> {
        let params = json!({
            "tx_hash": bs58::encode(tx_hash).into_string(), "sender_account_id": sender, "wait_until": "FINAL",
        });
        match self.post_raw("tx", params) {
            Ok(result) => {
                check_result_hash(&result, tx_hash)?;
                Ok(parse_outcome(&result).ok().map(|outcome| Outcome { tx_hash: Some(*tx_hash), ..outcome }))
            }
            Err(RpcFailure::Error(err)) if is_unknown_transaction(&err) => Ok(None),
            Err(e) => Err(e.into_error()),
        }
    }

    /// A call with the most gas a transaction can carry. Only the gas used is paid.
    pub fn call(&self, signer: &str, contract: &str, method: &str, args: Value, deposit: u128) -> Result<Outcome> {
        self.call_with_gas(signer, contract, method, args, 1000, deposit)
    }

    pub fn call_with_gas(
        &self,
        signer: &str,
        contract: &str,
        method: &str,
        args: Value,
        gas_tgas: u64,
        deposit: u128,
    ) -> Result<Outcome> {
        let gas = gas_tgas.checked_mul(TGAS).ok_or_else(|| anyhow!("too much gas"))?;
        let action = Action::Call { method: method.into(), args: args.to_string().into_bytes(), gas, deposit };
        self.send(signer, contract, vec![action])
    }
}

/// A local stand-in for a NEAR node, for tests of this crate and of the tools built on it.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use serde_json::{json, Value};

    type Answer = dyn Fn(&str, &Value) -> (u16, String) + Send + Sync;

    /// Answers each JSON-RPC request with `answer(method, params)`, which returns the HTTP status and the
    /// body, and records every method it receives.
    pub struct FakeRpc {
        pub url: String,
        methods: Arc<Mutex<Vec<String>>>,
    }

    impl FakeRpc {
        pub fn start(answer: impl Fn(&str, &Value) -> (u16, String) + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let url = format!("http://{}", listener.local_addr().expect("address"));
            let methods = Arc::new(Mutex::new(Vec::new()));
            let seen = methods.clone();
            let answer: Arc<Answer> = Arc::new(answer);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let Some(body) = read_request(&mut stream) else { continue };
                    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let method = request["method"].as_str().unwrap_or_default().to_string();
                    seen.lock().expect("lock").push(method.clone());
                    let (status, reply) = answer(&method, &request["params"]);
                    let extra = if (300..400).contains(&status) { "Location: http://127.0.0.1:1/\r\n" } else { "" };
                    let head = format!(
                        "HTTP/1.1 {status} X\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        reply.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(reply.as_bytes());
                }
            });
            Self { url, methods }
        }

        /// The methods received so far, in order.
        pub fn methods(&self) -> Vec<String> {
            self.methods.lock().expect("lock").clone()
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
        let mut request = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                return None;
            }
            request.extend_from_slice(&chunk[..read]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&request[..end]).to_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().to_string()))
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    return Some(request[end + 4..end + 4 + length].to_vec());
                }
            }
        }
    }

    /// A JSON-RPC success.
    pub fn ok(result: Value) -> (u16, String) {
        (200, json!({"jsonrpc": "2.0", "id": "1", "result": result}).to_string())
    }

    /// A JSON-RPC error.
    pub fn rpc_error(error: Value) -> (u16, String) {
        (200, json!({"jsonrpc": "2.0", "id": "1", "error": error}).to_string())
    }

    /// The answer to `view_access_key`: nonce 1 and a valid 32-byte block hash.
    pub fn access_key() -> (u16, String) {
        ok(json!({"nonce": 1, "block_hash": bs58::encode([4u8; 32]).into_string()}))
    }

    /// A final, successful transaction result.
    pub fn final_success() -> (u16, String) {
        ok(json!({"final_execution_status": "FINAL", "status": {"SuccessValue": ""}, "receipts_outcome": []}))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{access_key, final_success, ok, rpc_error, FakeRpc};
    use super::*;

    #[test]
    fn transaction_layout_follows_borsh() {
        let tx = encode_transaction("a.near", &[7; 32], 5, "b", &[9; 32], &[Action::Transfer(3)]);
        let mut expected = vec![6, 0, 0, 0];
        expected.extend_from_slice(b"a.near");
        expected.push(0);
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&5u64.to_le_bytes());
        expected.extend_from_slice(&[1, 0, 0, 0, b'b']);
        expected.extend_from_slice(&[9; 32]);
        expected.extend_from_slice(&[1, 0, 0, 0, 3]);
        expected.extend_from_slice(&3u128.to_le_bytes());
        assert_eq!(tx, expected);
    }

    #[test]
    fn call_action_layout() {
        let mut out = Vec::new();
        encode_action(&mut out, &Action::Call { method: "m".into(), args: b"{}".to_vec(), gas: 2, deposit: 1 });
        let mut expected = vec![2, 1, 0, 0, 0, b'm', 2, 0, 0, 0, b'{', b'}'];
        expected.extend_from_slice(&2u64.to_le_bytes());
        expected.extend_from_slice(&1u128.to_le_bytes());
        assert_eq!(out, expected);
    }

    #[test]
    fn outcome_adds_gas_and_decodes_the_value() {
        let result = json!({
            "final_execution_status": "FINAL",
            "status": {"SuccessValue": B64.encode("[true,false]")},
            "transaction_outcome": {"outcome": {"gas_burnt": TGAS}},
            "receipts_outcome": [{"outcome": {"gas_burnt": 2 * TGAS}}],
        });
        let outcome = parse_outcome(&result).unwrap();
        assert_eq!(outcome.tgas, 3.0);
        assert!(outcome.failure.is_none());
        assert_eq!(outcome.value, json!([true, false]));
    }

    fn encoded_key(key: &SigningKey) -> Vec<u8> {
        let mut bytes = key.to_bytes().to_vec();
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        bytes
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ona-near-{name}-{}", std::process::id()))
    }

    #[test]
    fn account_keys_are_validated() {
        let key = key();
        let text = format!("ed25519:{}", bs58::encode(encoded_key(&key)).into_string());
        assert_eq!(parse_account_key(&text).unwrap().to_bytes(), key.to_bytes());

        assert!(parse_account_key("secp256k1:abc").is_err());
        assert!(parse_account_key("ed25519:not-base-58!").is_err());
        assert!(parse_account_key(&format!("ed25519:{}", bs58::encode([1u8; 32]).into_string())).is_err());

        let mut wrong = encoded_key(&key);
        wrong[40] ^= 1;
        assert!(parse_account_key(&format!("ed25519:{}", bs58::encode(wrong).into_string())).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn an_account_key_readable_by_others_is_refused() {
        let path = temp_path("account-key");
        let key = SigningKey::from_bytes(&[6u8; 32]);
        fs::write(&path, format!("ed25519:{}\n", bs58::encode(encoded_key(&key)).into_string())).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_account_key(&path).unwrap_err().to_string().contains("other users"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_account_key(&path).is_ok());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn an_account_key_behind_a_link_or_not_a_file_is_refused() {
        let target = temp_path("link-target");
        let link = temp_path("link");
        fs::write(&target, format!("ed25519:{}\n", bs58::encode(encoded_key(&key())).into_string())).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(load_account_key(&target).is_ok());
        assert!(load_account_key(&link).is_err(), "a symbolic link must not be followed");
        fs::remove_file(&link).unwrap();
        fs::remove_file(&target).unwrap();

        let dir = temp_path("key-dir");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(load_account_key(&dir).is_err());
        fs::remove_dir(&dir).unwrap();
    }

    /// A final result with the given status and receipts.
    fn final_result(status: Value, receipts: Value) -> Value {
        json!({"final_execution_status": "FINAL", "status": status, "receipts_outcome": receipts})
    }

    #[test]
    fn a_failure_is_reported() {
        let outcome = parse_outcome(&final_result(json!({"Failure": {"ActionError": {}}}), json!([]))).unwrap();
        assert!(outcome.failure.is_some());
        assert!(outcome.require_all_receipts_ok().is_err());
    }

    #[test]
    fn a_status_without_an_explicit_success_is_an_error() {
        for status in [
            json!(null),
            json!({}),
            json!("NotStarted"),
            json!("Started"),
            json!({"SuccessReceiptId": "abc"}),
            json!({"SuccessValue": 7}),
            json!({"SuccessValue": "not base64!"}),
        ] {
            assert!(parse_outcome(&final_result(status.clone(), json!([]))).is_err(), "{status} must not read as a success");
        }
    }

    #[test]
    fn an_empty_success_value_is_a_success() {
        let outcome = parse_outcome(&final_result(json!({"SuccessValue": ""}), json!([]))).unwrap();
        assert!(outcome.failure.is_none());
        assert!(outcome.require_all_receipts_ok().is_ok());
        assert_eq!(outcome.value, Value::Null);
    }

    // The status only follows the promise the first receipt returned. A promise the contract detached, or a
    // sub-call its callback handled, can fail while the status says SuccessValue: the two are kept apart.
    #[test]
    fn a_failed_receipt_is_listed_apart_from_the_transaction_status() {
        let result = final_result(
            json!({"SuccessValue": ""}),
            json!([
                {"id": "first", "outcome": {"status": {"SuccessValue": ""}, "gas_burnt": 1}},
                {"id": "detached", "outcome": {"status": {"Failure": {"ActionError": {"kind": "AccountDoesNotExist"}}}}},
            ]),
        );
        let outcome = parse_outcome(&result).unwrap();
        assert!(outcome.failure.is_none(), "the transaction itself succeeded");
        assert_eq!(outcome.failed_receipts.len(), 1);
        assert!(outcome.failed_receipts[0].contains("detached"));
        let error = outcome.require_all_receipts_ok().unwrap_err();
        assert!(error.to_string().contains("detached"), "{error}");
    }

    #[test]
    fn a_result_must_say_it_is_final_and_list_its_receipts() {
        for level in ["NONE", "INCLUDED", "EXECUTED_OPTIMISTIC", "INCLUDED_FINAL", "EXECUTED"] {
            let result = json!({"final_execution_status": level, "status": {"SuccessValue": ""}, "receipts_outcome": []});
            assert!(parse_outcome(&result).is_err(), "{level} must not read as final");
        }
        assert!(parse_outcome(&json!({"status": {"SuccessValue": ""}, "receipts_outcome": []})).is_err());
        assert!(parse_outcome(&json!({"final_execution_status": "FINAL", "status": {"SuccessValue": ""}})).is_err());
        assert!(parse_outcome(&final_result(json!({"SuccessValue": ""}), json!([]))).is_ok());
    }

    // A "block hash" longer than 32 bytes, chosen by the node, could turn the signed bytes into another
    // transaction. Such a hash must never reach the encoder.
    #[test]
    fn a_block_hash_that_is_not_32_bytes_is_refused() {
        assert_eq!(decode_block_hash(&json!(bs58::encode([9u8; 32]).into_string())).unwrap(), [9u8; 32]);
        for bytes in [vec![9u8; 31], vec![9u8; 33], vec![9u8; 120], vec![]] {
            assert!(decode_block_hash(&json!(bs58::encode(bytes).into_string())).is_err());
        }
        assert!(decode_block_hash(&json!(null)).is_err());
        assert!(decode_block_hash(&json!("0OIl")).is_err());

        let mut long = vec![9u8; 32];
        long.extend_from_slice(&[1, 0, 0, 0, 2, 7, 0, 0, 0]);
        let hostile = bs58::encode(long).into_string();
        let rpc = FakeRpc::start(move |method, _| match method {
            "query" => ok(json!({"nonce": 41, "block_hash": hostile})),
            _ => final_success(),
        });
        let client = Client::new(&rpc.url, key());
        let error = client.send("signer.testnet", "mint.testnet", vec![Action::Transfer(1)]).err().unwrap();
        assert!(error.to_string().contains("32 bytes"), "{error}");
        assert_eq!(rpc.methods(), ["query"], "nothing may be signed and sent");
    }

    #[test]
    fn an_exhausted_nonce_is_an_error_not_a_panic() {
        let rpc = FakeRpc::start(|method, _| match method {
            "query" => ok(json!({"nonce": u64::MAX, "block_hash": bs58::encode([1u8; 32]).into_string()})),
            _ => final_success(),
        });
        let client = Client::new(&rpc.url, key());
        assert!(client.send("a.testnet", "b.testnet", vec![Action::Transfer(1)]).is_err());
        assert_eq!(rpc.methods(), ["query"]);
    }

    fn expected_hash() -> [u8; 32] {
        let body = encode_transaction("a.testnet", &key().verifying_key().to_bytes(), 2, "b.testnet", &[4u8; 32], &[Action::Transfer(1)]);
        Sha256::digest(&body).into()
    }

    #[test]
    fn send_returns_the_transaction_hash() {
        let rpc = FakeRpc::start(|method, _| if method == "query" { access_key() } else { final_success() });
        let client = Client::new(&rpc.url, key());
        let outcome = client.send("a.testnet", "b.testnet", vec![Action::Transfer(1)]).unwrap();
        assert_eq!(outcome.tx_hash, Some(expected_hash()));
        assert_eq!(rpc.methods(), ["query", "send_tx"]);
    }

    #[test]
    fn the_hash_is_known_before_anything_is_sent() {
        let rpc = FakeRpc::start(|method, _| if method == "query" { access_key() } else { final_success() });
        let client = Client::new(&rpc.url, key());
        let tx = client.sign_tx("a.testnet", "b.testnet", vec![Action::Transfer(1)]).unwrap();
        assert_eq!(tx.hash, expected_hash());
        assert_eq!(rpc.methods(), ["query"], "signed, not sent");
        assert_eq!(client.send_signed(&tx).unwrap().tx_hash, Some(expected_hash()));
        assert_eq!(rpc.methods(), ["query", "send_tx"]);
    }

    // After a timeout the transaction may still have run. The client asks for its status, and never sends
    // it again.
    #[test]
    fn after_a_timeout_the_status_is_asked_and_nothing_is_sent_twice() {
        let wanted = bs58::encode(expected_hash()).into_string();
        let rpc = FakeRpc::start(move |method, params| match method {
            "query" => access_key(),
            "send_tx" => (504, "gateway timeout".into()),
            "tx" if params["tx_hash"] == wanted.as_str() && params["sender_account_id"] == "a.testnet" => final_success(),
            _ => (500, "unexpected".into()),
        });
        let client = Client::new(&rpc.url, key()).with_status_checks(3, Duration::ZERO);
        let outcome = client.send("a.testnet", "b.testnet", vec![Action::Transfer(1)]).unwrap();
        assert_eq!(outcome.tx_hash, Some(expected_hash()));
        assert_eq!(rpc.methods(), ["query", "send_tx", "tx"]);
    }

    #[test]
    fn an_unknown_fate_is_reported_with_the_hash() {
        let rpc = FakeRpc::start(|method, _| match method {
            "query" => access_key(),
            "send_tx" => rpc_error(json!({"name": "HANDLER_ERROR", "cause": {"name": "TIMEOUT_ERROR"}})),
            _ => rpc_error(json!({"name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_TRANSACTION"}})),
        });
        let client = Client::new(&rpc.url, key()).with_status_checks(2, Duration::ZERO);
        let error = client.send("a.testnet", "b.testnet", vec![Action::Transfer(1)]).err().unwrap();
        let unknown = error.downcast_ref::<TxUnknown>().expect("a TxUnknown error");
        assert_eq!(unknown.hash, expected_hash());
        assert_eq!(rpc.methods(), ["query", "send_tx", "tx", "tx"]);

        // A result that is not final, or that does not say, is just as unclear: its fate is asked for.
        for answer in [
            json!({"final_execution_status": "INCLUDED", "status": "Started", "receipts_outcome": []}),
            json!({"final_execution_status": "EXECUTED_OPTIMISTIC", "status": {"SuccessValue": ""}, "receipts_outcome": []}),
            json!({"status": {"SuccessValue": ""}, "receipts_outcome": []}),
            json!({"final_execution_status": "FINAL", "status": {"SuccessValue": ""}}),
        ] {
            let rpc = FakeRpc::start(move |method, _| if method == "query" { access_key() } else { ok(answer.clone()) });
            let client = Client::new(&rpc.url, key()).with_status_checks(2, Duration::ZERO);
            let error = client.send("a.testnet", "b.testnet", vec![Action::Transfer(1)]).err().unwrap();
            assert_eq!(error.downcast_ref::<TxUnknown>().expect("a TxUnknown error").hash, expected_hash());
            assert_eq!(rpc.methods(), ["query", "send_tx", "tx", "tx"]);
        }
    }

    #[test]
    fn a_result_that_is_not_final_is_followed_by_a_status_check() {
        let rpc = FakeRpc::start(|method, _| match method {
            "query" => access_key(),
            "send_tx" => ok(json!({"final_execution_status": "INCLUDED", "status": "Started", "receipts_outcome": []})),
            _ => final_success(),
        });
        let client = Client::new(&rpc.url, key()).with_status_checks(3, Duration::ZERO);
        let outcome = client.send("a.testnet", "b.testnet", vec![Action::Transfer(1)]).unwrap();
        assert_eq!(outcome.tx_hash, Some(expected_hash()));
        assert_eq!(rpc.methods(), ["query", "send_tx", "tx"]);
    }

    #[test]
    fn a_clear_refusal_is_not_followed_by_status_checks() {
        let rpc = FakeRpc::start(|method, _| match method {
            "query" => access_key(),
            _ => rpc_error(json!({"name": "HANDLER_ERROR", "cause": {"name": "INVALID_TRANSACTION", "info": {}}})),
        });
        let client = Client::new(&rpc.url, key()).with_status_checks(3, Duration::ZERO);
        let error = client.send("a.testnet", "b.testnet", vec![Action::Transfer(1)]).err().unwrap();
        assert!(error.downcast_ref::<TxUnknown>().is_none());
        assert!(error.to_string().contains("INVALID_TRANSACTION"));
        assert_eq!(rpc.methods(), ["query", "send_tx"]);
    }

    // A result naming another transaction says nothing about ours: its fate is asked for, and the error
    // carries our hash.
    #[test]
    fn a_result_for_another_transaction_leads_to_a_status_check() {
        let other = || {
            ok(json!({
                "final_execution_status": "FINAL", "transaction": {"hash": "111"},
                "status": {"SuccessValue": ""}, "receipts_outcome": [],
            }))
        };
        let rpc = FakeRpc::start(move |method, _| if method == "query" { access_key() } else { other() });
        let client = Client::new(&rpc.url, key()).with_status_checks(2, Duration::ZERO);
        let error = client.send("a.testnet", "b.testnet", vec![Action::Transfer(1)]).err().unwrap();
        assert_eq!(error.downcast_ref::<TxUnknown>().expect("a TxUnknown error").hash, expected_hash());
        assert_eq!(rpc.methods(), ["query", "send_tx", "tx", "tx"]);

        let ours = bs58::encode(expected_hash()).into_string();
        let rpc = FakeRpc::start(move |method, _| match method {
            "query" => access_key(),
            "send_tx" => other(),
            _ => ok(json!({
                "final_execution_status": "FINAL", "transaction": {"hash": ours},
                "status": {"SuccessValue": ""}, "receipts_outcome": [],
            })),
        });
        let client = Client::new(&rpc.url, key()).with_status_checks(2, Duration::ZERO);
        assert_eq!(client.send("a.testnet", "b.testnet", vec![Action::Transfer(1)]).unwrap().tx_hash, Some(expected_hash()));
        assert_eq!(rpc.methods(), ["query", "send_tx", "tx"]);
    }

    #[test]
    fn the_body_of_an_http_error_is_read() {
        let rpc = FakeRpc::start(|_, _| (500, json!({"error": {"name": "INTERNAL_ERROR", "cause": {"name": "NODE_DOWN"}}}).to_string()));
        let error = Client::new(&rpc.url, key()).post("status", json!([])).unwrap_err();
        assert!(error.to_string().contains("NODE_DOWN"), "{error}");
    }

    #[test]
    fn only_https_or_a_local_address_is_accepted() {
        for url in [
            "https://rpc.testnet.near.org",
            "https://rpc.testnet.near.org:443/path",
            "HTTPS://RPC.example",
            "http://127.0.0.1:3030",
            "http://localhost:3030/",
            "http://[::1]:3030",
        ] {
            assert!(check_rpc_url(url).is_ok(), "{url}");
            assert!(check_tor_rpc_url(url).is_ok(), "{url}");
        }
        for url in [
            "http://rpc.testnet.near.org",
            "http://127.0.0.1.example.com",
            "http://localhost@evil.example",
            "https://user:pass@rpc.example",
            "http://10.0.0.1:3030",
            "ftp://rpc.example",
            "rpc.testnet.near.org",
            "https://",
            "https://rpc.example:x",
            "https://rpc.example /x",
            "http://[::1",
        ] {
            assert!(check_rpc_url(url).is_err(), "{url}");
            assert!(check_tor_rpc_url(url).is_err(), "{url}");
        }
        assert!(Client::connect("http://rpc.example", key()).is_err());
        let error = Client::new("http://rpc.example", key()).post("status", json!([])).unwrap_err();
        assert!(error.to_string().contains("not sent"), "{error}");
    }

    // Plain http to an onion address is safe only through Tor, which encrypts it end to end.
    #[test]
    fn http_to_an_onion_address_is_only_for_the_client_through_tor() {
        let onion = "http://abcdefghijklmnop.onion/";
        assert!(check_rpc_url(onion).is_err());
        assert!(check_tor_rpc_url(onion).is_ok());
        assert!(check_tor_rpc_url("http://.onion/").is_err());
        assert!(Client::connect(onion, key()).is_err());
        let error = Client::new(onion, key()).post("status", json!([])).unwrap_err();
        assert!(error.to_string().contains("not sent"), "{error}");
        assert!(Client::with_agent(onion, key(), ureq::Agent::new_with_defaults()).check_url().is_ok());
    }

    #[test]
    fn redirects_are_not_followed_and_environment_proxies_are_ignored() {
        let client = Client::new("http://127.0.0.1:1", key());
        assert_eq!(client.agent.config().max_redirects(), 0);
        assert!(client.agent.config().proxy().is_none());
        assert!(!client.agent.config().http_status_as_error());

        let target = FakeRpc::start(|_, _| ok(json!({"chain_id": "testnet"})));
        let redirecting = FakeRpc::start(|_, _| (302, String::new()));
        let error = Client::new(&redirecting.url, key()).post("status", json!([])).unwrap_err();
        assert!(error.to_string().contains("302"), "{error}");
        assert!(target.methods().is_empty());
    }

    #[test]
    fn account_ids_are_checked() {
        for id in ["ab", "mint.ona.testnet", "a-b_c.d", &"f".repeat(64), "0x1234567890abcdef1234567890abcdef12345678"] {
            assert!(check_account_id(id).is_ok(), "{id}");
        }
        for id in ["a", "", "Mint.testnet", ".a", "a.", "a..b", "a-.b", "a b", &"a".repeat(65), "guardian.tesnet!"] {
            assert!(check_account_id(id).is_err(), "{id}");
        }
        let rpc = FakeRpc::start(|_, _| final_success());
        assert!(Client::new(&rpc.url, key()).send("Bad", "b.testnet", vec![]).is_err());
        assert!(rpc.methods().is_empty());
    }

    #[test]
    fn mainnet_is_refused_from_the_chain_id_the_node_reports() {
        assert!(check_chain_id("testnet", "testnet").is_ok());
        assert!(check_chain_id("localnet", "localnet").is_ok());
        for (expected, reported) in
            [("testnet", "mainnet"), ("localnet", "MAINNET"), ("testnet", "localnet"), ("testnet", ""), ("mainnet", "mainnet"), ("", "")]
        {
            assert!(check_chain_id(expected, reported).is_err(), "{expected} {reported}");
        }

        let rpc = FakeRpc::start(|_, _| ok(json!({"chain_id": "mainnet"})));
        assert!(check_network(&Client::new(&rpc.url, key()), "testnet").is_err());
        let rpc = FakeRpc::start(|_, _| ok(json!({"chain_id": "testnet"})));
        assert_eq!(check_network(&Client::new(&rpc.url, key()), "testnet").unwrap(), "testnet");
        assert!(check_network(&Client::new(&rpc.url, key()), "mainnet").is_err());
        assert_eq!(rpc.methods(), ["status"], "an expected mainnet is refused before any request");
    }

    #[test]
    fn a_view_result_must_be_bytes() {
        let rpc = FakeRpc::start(|_, _| ok(json!({"result": [123, 125, 300]})));
        assert!(Client::new(&rpc.url, key()).view("a.testnet", "m", json!({})).is_err());
        let rpc = FakeRpc::start(|_, _| ok(json!({"result": [123, 125]})));
        assert_eq!(Client::new(&rpc.url, key()).view("a.testnet", "m", json!({})).unwrap(), json!({}));
    }
}
