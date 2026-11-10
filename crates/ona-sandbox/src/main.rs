//! Deploys `ona-mint` on a local `near-sandbox` node, runs every method with real transactions,
//! prints the gas burnt and checks the reserve after each step.
//!
//! The RPC client is written by hand (borsh by hand, HTTP over a local socket) because the usual
//! client crates cannot be unpacked in this build sandbox.

use std::io::{Read, Write};
use std::net::TcpStream;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ona_token::{
    claim_digest, keygen, redeem_digest, sign_blinded, sign_digest, spend_digest, token_dst,
    ChangeOut, PendingToken, SecretKey, Token, G2_LEN,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MILLI: u128 = NEAR / 1000;
const UNIT: u128 = 100 * MILLI;
const TGAS: u64 = 1_000_000_000_000;
const STORAGE_PER_TOKEN: u128 = MILLI;
const ISSUE_FEE_PER_TOKEN: u128 = 2 * MILLI;
const WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32-unknown-unknown/contract/ona_mint.wasm"
);

struct Rpc {
    host_port: String,
}

impl Rpc {
    fn post(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc":"2.0","id":"1","method":method,"params":params}).to_string();
        let mut stream = TcpStream::connect(&self.host_port).context("connect to sandbox")?;
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, payload) = text.split_once("\r\n\r\n").ok_or_else(|| anyhow!("bad HTTP response"))?;
        let payload = if head.to_lowercase().contains("transfer-encoding: chunked") {
            dechunk(payload)?
        } else {
            payload.to_string()
        };
        let v: Value = serde_json::from_str(&payload).with_context(|| format!("JSON: {payload}"))?;
        if let Some(err) = v.get("error") {
            bail!("rpc error: {err}");
        }
        Ok(v["result"].clone())
    }

    fn query(&self, params: Value) -> Result<Value> {
        self.post("query", params)
    }

    fn view(&self, account: &str, method: &str, args: Value) -> Result<Value> {
        let r = self.query(json!({
            "request_type":"call_function","finality":"optimistic","account_id":account,
            "method_name":method,"args_base64":B64.encode(args.to_string()),
        }))?;
        let bytes: Vec<u8> = r["result"]
            .as_array()
            .ok_or_else(|| anyhow!("view failed: {r}"))?
            .iter()
            .map(|b| b.as_u64().unwrap_or(0) as u8)
            .collect();
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn balance(&self, account: &str) -> Result<Option<u128>> {
        match self.query(json!({"request_type":"view_account","finality":"optimistic","account_id":account})) {
            Ok(r) => Ok(Some(r["amount"].as_str().unwrap_or("0").parse()?)),
            Err(e) if e.to_string().contains("UNKNOWN_ACCOUNT") => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn dechunk(mut s: &str) -> Result<String> {
    let mut out = String::new();
    loop {
        let (len, rest) = s.split_once("\r\n").ok_or_else(|| anyhow!("bad chunk"))?;
        let n = usize::from_str_radix(len.trim(), 16)?;
        if n == 0 {
            return Ok(out);
        }
        out.push_str(&rest[..n]);
        s = &rest[n + 2..];
    }
}

enum Action {
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

fn encode_action(out: &mut Vec<u8>, a: &Action) {
    match a {
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

struct Chain {
    rpc: Rpc,
    key: SigningKey,
}

struct Outcome {
    tgas: f64,
    failure: Option<String>,
    value: Value,
}

impl Chain {
    fn pk(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn send(&self, signer: &str, receiver: &str, actions: Vec<Action>) -> Result<Outcome> {
        let pk = format!("ed25519:{}", bs58::encode(self.pk()).into_string());
        let info = self.rpc.query(json!({
            "request_type":"view_access_key","finality":"optimistic",
            "account_id":signer,"public_key":pk,
        }))?;
        if info.get("error").is_some() {
            bail!("no key for {signer}: {info}");
        }
        let nonce = info["nonce"].as_u64().ok_or_else(|| anyhow!("nonce: {info}"))? + 1;
        let hash = bs58::decode(info["block_hash"].as_str().unwrap_or_default()).into_vec()?;

        let mut tx = Vec::new();
        put_str(&mut tx, signer.as_bytes());
        tx.push(0);
        tx.extend_from_slice(&self.pk());
        tx.extend_from_slice(&nonce.to_le_bytes());
        put_str(&mut tx, receiver.as_bytes());
        tx.extend_from_slice(&hash);
        tx.extend_from_slice(&(actions.len() as u32).to_le_bytes());
        for a in &actions {
            encode_action(&mut tx, a);
        }
        let digest: [u8; 32] = Sha256::digest(&tx).into();
        let sig = self.key.sign(&digest).to_bytes();
        let mut signed = tx;
        signed.push(0);
        signed.extend_from_slice(&sig);

        let r = self.rpc.post("broadcast_tx_commit", json!([B64.encode(&signed)]))?;
        let mut burnt = r["transaction_outcome"]["outcome"]["gas_burnt"].as_u64().unwrap_or(0);
        for receipt in r["receipts_outcome"].as_array().into_iter().flatten() {
            burnt += receipt["outcome"]["gas_burnt"].as_u64().unwrap_or(0);
        }
        let failure = r["status"].get("Failure").map(|f| f.to_string());
        let value = r["status"]
            .get("SuccessValue")
            .and_then(|v| v.as_str())
            .and_then(|v| B64.decode(v).ok())
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or(Value::Null);
        Ok(Outcome { tgas: burnt as f64 / TGAS as f64, failure, value })
    }

    fn call(&self, signer: &str, contract: &str, method: &str, args: Value, deposit: u128) -> Result<Outcome> {
        self.send(
            signer,
            contract,
            vec![Action::Call {
                method: method.into(),
                args: args.to_string().into_bytes(),
                gas: 1000 * TGAS,
                deposit,
            }],
        )
    }
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn token_json(t: &Token) -> Value {
    json!({"denom_id":t.denom_id,"pk":b64(&t.pk),"nonce":b64(&t.nonce),"sig":b64(&t.sig)})
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Env {
    chain: Chain,
    mint: String,
    signer: String,
    relay: String,
    guardian: String,
    alice: String,
    bob: String,
    sks: Vec<SecretKey>,
    pks: Vec<[u8; G2_LEN]>,
    dst: Vec<u8>,
    rows: Vec<(String, f64)>,
    last_margin: i128,
}

impl Env {
    fn record(&mut self, label: &str, o: &Outcome) -> Result<()> {
        if let Some(f) = &o.failure {
            bail!("{label} failed: {f}");
        }
        self.rows.push((label.to_string(), o.tgas));
        self.check_reserve(label)
    }

    /// Invariant I1 on the real runtime, including real storage accounting.
    fn check_reserve(&mut self, label: &str) -> Result<()> {
        let s = self.chain.rpc.view(&self.mint, "reserve_status", json!({}))?;
        let n = |k: &str| -> Result<i128> { Ok(s[k].as_str().unwrap_or("0").parse()?) };
        let margin = n("balance")? - n("storage_cost")? - n("liabilities")?;
        if s["solvent"] != json!(true) {
            bail!("I1 broken after {label}: {s}");
        }
        if margin < self.last_margin {
            bail!("I1 margin fell after {label}: {} -> {margin}", self.last_margin);
        }
        self.last_margin = margin;
        Ok(())
    }

    fn deposit(&mut self, denom: u8, n: usize) -> Result<(u64, Vec<PendingToken>)> {
        let tokens: Vec<PendingToken> =
            (0..n).map(|_| PendingToken::new(&mut OsRng, denom, &self.dst)).collect::<Result<_, _>>().map_err(|e| anyhow!("{e}"))?;
        let blinded: Vec<String> = tokens.iter().map(|t| b64(&t.blinded)).collect();
        let cost = n as u128 * ((UNIT << denom) + STORAGE_PER_TOKEN + ISSUE_FEE_PER_TOKEN) + NEAR / 10;
        let (alice, mint) = (self.alice.clone(), self.mint.clone());
        let o = self.chain.call(&alice, &mint, "deposit", json!({"denom_id":denom,"blinded":blinded}), cost)?;
        self.record(&format!("deposit x{n}"), &o)?;
        let id: u64 = o.value.as_str().ok_or_else(|| anyhow!("deposit id: {}", o.value))?.parse()?;
        Ok((id, tokens))
    }

    fn issue(&mut self, denom: u8, n: usize) -> Result<Vec<(Token, SigningKey)>> {
        let (id, pending) = self.deposit(denom, n)?;
        let sigs: Vec<[u8; 48]> = pending
            .iter()
            .map(|p| sign_blinded(&self.sks[denom as usize], &p.blinded))
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow!("{e}"))?;
        let args: Vec<String> = sigs.iter().map(|s| b64(s)).collect();
        let (signer, mint) = (self.signer.clone(), self.mint.clone());
        let o = self.chain.call(&signer, &mint, "lock", json!({"deposit_id":id.to_string()}), 0)?;
        self.record("lock", &o)?;
        let o = self.chain.call(&signer, &mint, "issue", json!({"deposit_id":id.to_string(),"sigs":args}), 0)?;
        self.record(&format!("issue x{n}"), &o)?;
        let pk = self.pks[denom as usize];
        pending
            .into_iter()
            .zip(sigs)
            .map(|(p, s)| p.finish(&s, &pk).map_err(|e| anyhow!("{e}")))
            .collect()
    }

    fn redeem(&mut self, t: &Token, owner: &SigningKey) -> Result<Outcome> {
        let (bob, mint) = (self.bob.clone(), self.mint.clone());
        let d = redeem_digest(&mint, &bob, &t.nullifier());
        self.chain.call(&bob, &mint, "redeem", json!({"token":token_json(t),"owner_sig":b64(&sign_digest(owner, &d))}), 0)
    }

    fn spend_call(&mut self, t: &Token, owner: &SigningKey, to: &str, amount: u128, fee: u128, change: &[ChangeOut]) -> Result<Outcome> {
        let d = spend_digest(&self.mint, &self.relay, t.denom_id, &t.nullifier(), to, amount, fee, change);
        let change_json: Vec<Value> = change.iter().map(|c| json!({"denom_id":c.denom_id,"blinded":b64(&c.blinded)})).collect();
        let (relay, mint) = (self.relay.clone(), self.mint.clone());
        self.chain.call(
            &relay,
            &mint,
            "spend",
            json!({
                "token":token_json(t),"owner_sig":b64(&sign_digest(owner, &d)),"to":to,
                "amount":amount.to_string(),"fee":fee.to_string(),"change":change_json,
            }),
            0,
        )
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = near_sandbox::SandboxConfig {
        additional_config: Some(json!({"telemetry": {"endpoints": []}})),
        ..Default::default()
    };
    let sandbox = near_sandbox::Sandbox::start_sandbox_with_config(config)
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    let host_port = sandbox.rpc_addr.trim_start_matches("http://").trim_end_matches('/').to_string();
    let rpc = Rpc { host_port };

    let genesis = near_sandbox::GenesisAccount::default();
    let root = genesis.account_id.to_string();
    let secret = genesis.private_key.to_string();
    let raw = bs58::decode(secret.trim_start_matches("ed25519:")).into_vec()?;
    let seed: [u8; 32] = raw[..32].try_into()?;
    let chain = Chain { rpc, key: SigningKey::from_bytes(&seed) };

    let sub = |name: &str| format!("{name}.{root}");
    for name in ["signer", "relay", "guardian", "alice", "bob"] {
        let actions = vec![Action::Create, Action::Transfer(500 * NEAR), Action::AddFullKey(chain.pk())];
        let o = chain.send(&root, &sub(name), actions)?;
        if let Some(f) = o.failure {
            bail!("create {name}: {f}");
        }
    }

    let code = std::fs::read(WASM).context("build the wasm first")?;
    println!("wasm size: {} bytes", code.len());
    let sks: Vec<SecretKey> = (0..4).map(|_| keygen(&mut OsRng)).collect();
    let pks: Vec<[u8; G2_LEN]> = sks.iter().map(|k| k.public_key()).collect();
    let mint = sub("mint");
    let denoms: Vec<Value> = pks
        .iter()
        .enumerate()
        .map(|(i, pk)| {
            json!({
                "value":(UNIT << i).to_string(),"pk_g2":b64(pk),
                "circulation_cap":1000,"hourly_redeem_cap":1000,
            })
        })
        .collect();
    let init = json!({
        "denoms":denoms,"signer":sub("signer"),"relay":sub("relay"),
        "guardian":sub("guardian"),"network":"sandbox",
    });
    let new_call = Action::Call {
        method: "new".into(),
        args: init.to_string().into_bytes(),
        gas: 300 * TGAS,
        deposit: 0,
    };
    let actions = vec![Action::Create, Action::Transfer(20 * NEAR), Action::Deploy(code), new_call];
    let o = chain.send(&root, &mint, actions)?;
    if let Some(f) = &o.failure {
        bail!("deploy: {f}");
    }

    let keys = chain.rpc.query(json!({"request_type":"view_access_key_list","finality":"optimistic","account_id":mint}))?;
    let key_count = keys["keys"].as_array().map_or(usize::MAX, Vec::len);
    println!("access keys on the mint account: {key_count}");

    let dst = token_dst("sandbox", &mint).map_err(|e| anyhow!("{e}"))?;
    let (signer, relay, guardian, alice, bob) = (sub("signer"), sub("relay"), sub("guardian"), sub("alice"), sub("bob"));
    let mut e = Env { chain, mint: mint.clone(), signer, relay: relay.clone(), guardian, alice, bob: bob.clone(), sks, pks, dst, rows: vec![], last_margin: i128::MIN };
    e.rows.push(("deploy + new (4 denominations)".into(), o.tgas));
    e.check_reserve("deploy")?;

    for n in [1usize, 2, 8, 64] {
        e.issue(0, n)?;
    }

    // redeem pays the owner's implicit account, which did not exist before.
    let mut batch = e.issue(1, 8)?;
    let (t, owner) = batch.pop().unwrap();
    let implicit = hex(&t.pk);
    if e.chain.rpc.balance(&implicit)?.is_some() {
        bail!("implicit account unexpectedly exists");
    }
    let o = e.redeem(&t, &owner)?;
    e.record("redeem", &o)?;
    let got = e.chain.rpc.balance(&implicit)?.ok_or_else(|| anyhow!("implicit account not created"))?;
    println!("redeem paid the implicit account: {got} yocto (expected {})", (UNIT << 1) - 10 * MILLI);

    let o = e.redeem(&t, &owner)?;
    println!("double redeem refused: {}", o.failure.is_some());
    e.check_reserve("double redeem")?;

    let (t, owner) = batch.pop().unwrap();
    let mut forged = t.clone();
    forged.nonce[0] ^= 1;
    let o = e.redeem(&forged, &owner)?;
    println!("forged token refused: {}", o.failure.is_some());
    e.check_reserve("forged")?;

    let o = e.chain.call(&bob, &mint, "on_spend_payout", json!({"owner":bob,"amount":"1"}), 0)?;
    println!("payout callback refused for an outsider: {}", o.failure.is_some());
    e.check_reserve("outside callback")?;

    // spend without change
    let (t, owner) = batch.pop().unwrap();
    let fee = 20 * MILLI;
    let before = e.chain.rpc.balance(&bob)?.unwrap_or(0);
    let o = e.spend_call(&t, &owner, &bob, (UNIT << 1) - fee, fee, &[])?;
    e.record("spend, no change", &o)?;
    println!("spend paid the recipient: {} yocto", e.chain.rpc.balance(&bob)?.unwrap_or(0) - before);

    // spend with change, then the change is issued and redeemed
    let (t, owner) = batch.pop().unwrap();
    let pending = PendingToken::new(&mut OsRng, 0, &e.dst).map_err(|x| anyhow!("{x}"))?;
    let change = [ChangeOut { denom_id: 0, blinded: pending.blinded }];
    let fee = 50 * MILLI;
    let o = e.spend_call(&t, &owner, &bob, UNIT - fee, fee, &change)?;
    e.record("spend, 1 change", &o)?;
    let list = e.chain.rpc.view(&mint, "pending_deposits", json!({"from":"0","limit":64}))?;
    let id = list.as_array().and_then(|l| l.last()).map(|r| r["id"].clone()).ok_or_else(|| anyhow!("no pending record"))?;
    let sig = sign_blinded(&e.sks[0], &pending.blinded).map_err(|x| anyhow!("{x}"))?;
    let signer = e.signer.clone();
    let o = e.chain.call(&signer, &mint, "lock", json!({"deposit_id":id.clone()}), 0)?;
    e.record("lock the change", &o)?;
    let o = e.chain.call(&signer, &mint, "issue", json!({"deposit_id":id,"sigs":[b64(&sig)]}), 0)?;
    e.record("issue the change", &o)?;
    let pk0 = e.pks[0];
    let (ct, change_owner) = pending.finish(&sig, &pk0).map_err(|x| anyhow!("{x}"))?;
    let o = e.redeem(&ct, &change_owner)?;
    e.record("redeem the change", &o)?;

    // spend to an account that does not exist
    let (t, owner) = batch.pop().unwrap();
    let ghost = format!("ghost-does-not-exist.{root}");
    let before = e.chain.rpc.balance(&mint)?.unwrap_or(0);
    let fee = 20 * MILLI;
    let amount = (UNIT << 1) - fee;
    let o = e.spend_call(&t, &owner, &ghost, amount, fee, &[])?;
    let after = e.chain.rpc.balance(&mint)?.unwrap_or(0);
    let returned = e.chain.rpc.balance(&hex(&t.pk))?.unwrap_or(0);
    println!(
        "spend to a missing account: top-level failure={:?}, mint balance change {} yocto, returned to the owner {returned} of {amount}",
        o.failure.is_some(),
        after as i128 - before as i128
    );
    e.check_reserve("spend to missing account")?;

    // relay batches
    for n in [1usize, 8, 32] {
        let tokens = e.issue(2, if n == 1 { 1 } else { n })?;
        let items: Vec<Value> = tokens
            .iter()
            .map(|(t, o)| {
                let d = claim_digest(&mint, &relay, &t.nullifier());
                json!({"token":token_json(t),"owner_sig":b64(&sign_digest(o, &d))})
            })
            .collect();
        let o = e.chain.call(&relay, &mint, "relay_claim", json!({"items":items}), 0)?;
        e.record(&format!("relay_claim x{n}"), &o)?;
        let ok = o.value.as_array().map_or(0, |v| v.iter().filter(|b| **b == json!(true)).count());
        println!("relay_claim x{n}: {ok} accepted");
    }

    let guardian = e.guardian.clone();
    let o = e.chain.call(&guardian, &mint, "halt", json!({}), 0)?;
    e.record("halt", &o)?;
    let cost = UNIT + NEAR;
    let pending = PendingToken::new(&mut OsRng, 0, &e.dst).map_err(|x| anyhow!("{x}"))?;
    let alice = e.alice.clone();
    let o = e.chain.call(&alice, &mint, "deposit", json!({"denom_id":0,"blinded":[b64(&pending.blinded)]}), cost)?;
    println!("deposit refused after halt: {}", o.failure.is_some());

    println!("\ngas burnt per transaction (Tgas):");
    for (label, tgas) in &e.rows {
        println!("  {label:<34} {tgas:>9.3}");
    }
    let s = e.chain.rpc.view(&mint, "reserve_status", json!({}))?;
    println!("\nfinal reserve: {s}");
    Ok(())
}
