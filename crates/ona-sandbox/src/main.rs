//! Deploys `ona-mint` on a local `near-sandbox` node, runs every method with real transactions,
//! prints the gas burnt and checks the reserve after each step. It then runs the real signer loop
//! and the real relay exchange against the same node.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use ona_near::{Action, Client, Outcome};
use ona_server::mock::MockModel;
use ona_server::near::NearRelayChain;
use ona_server::{Config, MemoryStore, Relay};
use ona_signer::near::NearChain;
use ona_signer::{KeyStore, MemoryDurable, Signer};
use ona_token::{
    blind, claim_digest, keygen, redeem_digest, sign_blinded, sign_digest, spend_digest, token_dst, unblind,
    ChangeOut, PendingToken, SecretKey, Token, G1_LEN, G2_LEN,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MILLI: u128 = NEAR / 1000;
const UNIT: u128 = 100 * MILLI;
const STORAGE_PER_TOKEN: u128 = MILLI;
const ISSUE_FEE_PER_TOKEN: u128 = 2 * MILLI;
const WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32-unknown-unknown/contract/ona_mint.wasm"
);

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
    chain: Client,
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
        let s = self.chain.view(&self.mint, "reserve_status", json!({}))?;
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
    let rpc_url = sandbox.rpc_addr.trim_end_matches('/').to_string();

    let genesis = near_sandbox::GenesisAccount::default();
    let root = genesis.account_id.to_string();
    let secret = genesis.private_key.to_string();
    let raw = bs58::decode(secret.trim_start_matches("ed25519:")).into_vec()?;
    let seed: [u8; 32] = raw[..32].try_into()?;
    let chain = Client::new(&rpc_url, SigningKey::from_bytes(&seed));

    let sub = |name: &str| format!("{name}.{root}");
    for name in ["signer", "relay", "guardian", "alice", "bob"] {
        let actions = vec![Action::Create, Action::Transfer(500 * NEAR), Action::AddFullKey(chain.public_key())];
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
    // The same plan as the real deployment tool, so this run also covers it.
    let plan = ona_deploy::MintPlan {
        network: "sandbox".into(),
        signer: sub("signer"),
        relay: sub("relay"),
        guardian: sub("guardian"),
        denom_keys: pks.clone(),
        base_value: UNIT,
        circulation_cap: 1000,
        hourly_redeem_cap: 1000,
        funding: 20 * NEAR,
    };
    let o = chain.send(&root, &mint, plan.actions(code)?)?;
    if let Some(f) = &o.failure {
        bail!("deploy: {f}");
    }

    let keys = chain.query(json!({"request_type":"view_access_key_list","finality":"optimistic","account_id":mint}))?;
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
    if e.chain.balance(&implicit)?.is_some() {
        bail!("implicit account unexpectedly exists");
    }
    let o = e.redeem(&t, &owner)?;
    e.record("redeem", &o)?;
    let got = e.chain.balance(&implicit)?.ok_or_else(|| anyhow!("implicit account not created"))?;
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
    let before = e.chain.balance(&bob)?.unwrap_or(0);
    let o = e.spend_call(&t, &owner, &bob, (UNIT << 1) - fee, fee, &[])?;
    e.record("spend, no change", &o)?;
    println!("spend paid the recipient: {} yocto", e.chain.balance(&bob)?.unwrap_or(0) - before);

    // spend with change, then the change is issued and redeemed
    let (t, owner) = batch.pop().unwrap();
    let pending = PendingToken::new(&mut OsRng, 0, &e.dst).map_err(|x| anyhow!("{x}"))?;
    let change = [ChangeOut { denom_id: 0, blinded: pending.blinded }];
    let fee = 50 * MILLI;
    let o = e.spend_call(&t, &owner, &bob, UNIT - fee, fee, &change)?;
    e.record("spend, 1 change", &o)?;
    let list = e.chain.view(&mint, "pending_deposits", json!({"from":"0","limit":64}))?;
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
    let before = e.chain.balance(&mint)?.unwrap_or(0);
    let fee = 20 * MILLI;
    let amount = (UNIT << 1) - fee;
    let o = e.spend_call(&t, &owner, &ghost, amount, fee, &[])?;
    let after = e.chain.balance(&mint)?.unwrap_or(0);
    let returned = e.chain.balance(&hex(&t.pk))?.unwrap_or(0);
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

    // The real signer loop: it finds a deposit, locks it, reads the lock back, then issues.
    let issued_before = e.chain.view(&mint, "get_denom", json!({"denom_id":0}))?["counters"]["issued"].as_u64().unwrap_or(0);
    e.deposit(0, 2)?;
    let keys: Vec<SecretKey> = e
        .sks
        .iter()
        .map(|k| SecretKey::from_bytes(&k.to_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|x| anyhow!("{x}"))?;
    let mut near_chain = NearChain::new(Client::new(&rpc_url, SigningKey::from_bytes(&seed)), e.signer.clone(), mint.clone());
    let mut signer_loop = Signer::new(KeyStore::from_keys(keys), MemoryDurable::default());
    signer_loop.check_keys(&mut near_chain).map_err(|x| anyhow!(x))?;
    let mut issued = false;
    for _ in 0..60 {
        let report = signer_loop.tick(&mut near_chain).map_err(|x| anyhow!(x))?;
        if !report.skipped.is_empty() {
            println!("signer skipped: {:?}", report.skipped);
        }
        if !report.issued.is_empty() {
            issued = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let issued_after = e.chain.view(&mint, "get_denom", json!({"denom_id":0}))?["counters"]["issued"].as_u64().unwrap_or(0);
    println!("real signer loop issued: {issued}, tokens {issued_before} -> {issued_after}");
    if !issued || issued_after != issued_before + 2 {
        bail!("the signer loop did not issue the deposit");
    }
    e.check_reserve("signer loop")?;

    // The real relay: credit claimed on chain, request tokens signed, then one model call.
    let (credit, credit_owner) = e.issue(0, 1)?.pop().ok_or_else(|| anyhow!("no credit"))?;
    let relay_chain = NearRelayChain::new(Client::new(&rpc_url, SigningKey::from_bytes(&seed)), relay.clone(), mint.clone());
    let config = Config {
        mint: mint.clone(),
        relay: relay.clone(),
        mint_dst: e.dst.clone(),
        credit_key: e.pks[0],
        tokens_per_credit: 2,
        max_tokens_per_request: 100,
    };
    let mut relay_node = Relay::new(MemoryStore::default(), relay_chain, MockModel, config, keygen(&mut OsRng));
    let request_dst = relay_node.request_dst().to_vec();
    let mut wallet = Vec::new();
    for _ in 0..2 {
        let mut x = [0u8; 32];
        OsRng.fill_bytes(&mut x);
        let (r, point) = blind(&x, &request_dst, &mut OsRng);
        wallet.push((x, r, hex(&point)));
    }
    let digest = claim_digest(&mint, &relay, &credit.nullifier());
    let body = json!({
        "token": hex(&credit.to_bytes()),
        "owner_sig": hex(&sign_digest(&credit_owner, &digest)),
        "blinded": wallet.iter().map(|w| w.2.clone()).collect::<Vec<_>>(),
    });
    let (status, reply) = relay_node.exchange(&body);
    if status != 202 {
        bail!("exchange not accepted: {status} {reply}");
    }
    let claimed = relay_node.flush().map_err(|x| anyhow!(x))?;
    let (status, reply) = relay_node.exchange(&body);
    println!("real relay exchange: {claimed} claim accepted on chain, status {status}");
    if status != 200 {
        bail!("exchange did not complete: {status} {reply}");
    }
    e.check_reserve("relay exchange")?;
    let spent_by_relay = e.chain.view(&mint, "spent_by_relay", json!({"nf":b64(&credit.nullifier())}))?;
    println!("nullifier recorded as claimed by the relay: {spent_by_relay}");

    let sig_hex = reply["signatures"][0].as_str().ok_or_else(|| anyhow!("no signature"))?;
    let sig_bytes: Vec<u8> = (0..sig_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16))
        .collect::<Result<_, _>>()?;
    let blind_sig: [u8; G1_LEN] = sig_bytes.try_into().map_err(|_| anyhow!("bad signature length"))?;
    let unblinded = unblind(&blind_sig, &wallet[0].1).map_err(|x| anyhow!("{x}"))?;
    let mut request_token = wallet[0].0.to_vec();
    request_token.extend_from_slice(&unblinded);
    let (status, reply) = relay_node.chat(&json!({"token":hex(&request_token),"prompt":"bonjour"}));
    println!("chat with a request token: status {status}, {reply}");
    if status != 200 {
        bail!("chat failed: {status} {reply}");
    }
    let (status, _) = relay_node.chat(&json!({"token":hex(&request_token),"prompt":"encore"}));
    println!("same request token used twice: status {status}");

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
    let s = e.chain.view(&mint, "reserve_status", json!({}))?;
    println!("\nfinal reserve: {s}");
    Ok(())
}
