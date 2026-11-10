//! A small blocking NEAR RPC client: JSON-RPC calls and hand-encoded, ed25519-signed transactions.
//! Only the actions ONA needs are supported.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const TGAS: u64 = 1_000_000_000_000;
const RPC_TIMEOUT: Duration = Duration::from_secs(120);

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
pub fn encode_transaction(
    signer: &str,
    public_key: &[u8; 32],
    nonce: u64,
    receiver: &str,
    block_hash: &[u8],
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

/// The result of a transaction once all its receipts have run.
pub struct Outcome {
    pub tgas: f64,
    pub failure: Option<String>,
    pub value: Value,
}

/// Reads a `broadcast_tx_commit` result.
pub fn parse_outcome(result: &Value) -> Outcome {
    let mut burnt = result["transaction_outcome"]["outcome"]["gas_burnt"].as_u64().unwrap_or(0);
    for receipt in result["receipts_outcome"].as_array().into_iter().flatten() {
        burnt += receipt["outcome"]["gas_burnt"].as_u64().unwrap_or(0);
    }
    let failure = result["status"].get("Failure").map(|f| f.to_string());
    let value = result["status"]
        .get("SuccessValue")
        .and_then(|v| v.as_str())
        .and_then(|v| B64.decode(v).ok())
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or(Value::Null);
    Outcome { tgas: burnt as f64 / TGAS as f64, failure, value }
}

pub struct Client {
    url: String,
    agent: ureq::Agent,
    key: SigningKey,
}

impl Client {
    pub fn new(url: &str, key: SigningKey) -> Self {
        let agent: ureq::Agent =
            ureq::Agent::config_builder().timeout_global(Some(RPC_TIMEOUT)).build().into();
        Self { url: url.to_string(), agent, key }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn post(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc":"2.0","id":"1","method":method,"params":params}).to_string();
        let text = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .send(body)
            .context("RPC request failed")?
            .body_mut()
            .read_to_string()
            .context("cannot read RPC response")?;
        let value: Value = serde_json::from_str(&text).with_context(|| format!("not JSON: {text}"))?;
        if let Some(err) = value.get("error") {
            bail!("rpc error: {err}");
        }
        Ok(value["result"].clone())
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
            .map(|b| b.as_u64().unwrap_or(0) as u8)
            .collect();
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn view(&self, account: &str, method: &str, args: Value) -> Result<Value> {
        self.view_at("optimistic", account, method, args)
    }

    /// A view on a final block. Use it for anything a signature or a payment depends on.
    pub fn view_final(&self, account: &str, method: &str, args: Value) -> Result<Value> {
        self.view_at("final", account, method, args)
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

    pub fn send(&self, signer: &str, receiver: &str, actions: Vec<Action>) -> Result<Outcome> {
        let public_key = self.public_key();
        let info = self.query(json!({
            "request_type":"view_access_key","finality":"optimistic","account_id":signer,
            "public_key":format!("ed25519:{}", bs58::encode(public_key).into_string()),
        }))?;
        if info.get("error").is_some() {
            bail!("no key for {signer}: {info}");
        }
        let nonce = info["nonce"].as_u64().ok_or_else(|| anyhow!("no nonce: {info}"))? + 1;
        let hash = bs58::decode(info["block_hash"].as_str().unwrap_or_default()).into_vec()?;

        let mut signed = encode_transaction(signer, &public_key, nonce, receiver, &hash, &actions);
        let digest: [u8; 32] = Sha256::digest(&signed).into();
        let signature = self.key.sign(&digest).to_bytes();
        signed.push(0);
        signed.extend_from_slice(&signature);

        let result = self.post("broadcast_tx_commit", json!([B64.encode(&signed)]))?;
        Ok(parse_outcome(&result))
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
        let action = Action::Call {
            method: method.into(),
            args: args.to_string().into_bytes(),
            gas: gas_tgas * TGAS,
            deposit,
        };
        self.send(signer, contract, vec![action])
    }
}

#[cfg(test)]
mod tests {
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
            "status": {"SuccessValue": B64.encode("[true,false]")},
            "transaction_outcome": {"outcome": {"gas_burnt": TGAS}},
            "receipts_outcome": [{"outcome": {"gas_burnt": 2 * TGAS}}],
        });
        let outcome = parse_outcome(&result);
        assert_eq!(outcome.tgas, 3.0);
        assert!(outcome.failure.is_none());
        assert_eq!(outcome.value, json!([true, false]));
    }

    #[test]
    fn a_failure_is_reported() {
        let result = json!({"status": {"Failure": {"ActionError": {}}}});
        assert!(parse_outcome(&result).failure.is_some());
    }
}
