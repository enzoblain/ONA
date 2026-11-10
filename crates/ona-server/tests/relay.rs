use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use ona_server::*;
use ona_token::{
    blind, claim_digest, keygen, sign_blinded, sign_digest, unblind, verify, BlindingFactor,
    PendingToken, SecretKey, Token, G1_LEN, G2_LEN,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};

const MINT: &str = "mint.test";
const RELAY: &str = "relay.test";
const Q: usize = 3;
const MINT_DST: &[u8] = b"ONA-MINT-V1:sandbox:mint.test:BLS12381G1_XMD:SHA-256_SSWU_RO_";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[derive(Default)]
struct FakeChain {
    spent: BTreeSet<[u8; 32]>,
    by_relay: BTreeSet<[u8; 32]>,
    calls: usize,
    fail: bool,
    /// Claims land on chain, but the reply is lost, as in a crash during the call.
    lose_reply: bool,
}

impl Chain for FakeChain {
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        Ok(self.spent.contains(nf))
    }
    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
        if self.fail {
            return Err("rpc down".into());
        }
        self.calls += 1;
        let out = claims
            .iter()
            .map(|c| {
                let nf = c.token.nullifier();
                let fresh = self.spent.insert(nf);
                if fresh {
                    self.by_relay.insert(nf);
                }
                fresh
            })
            .collect();
        if self.lose_reply {
            return Err("connection lost".into());
        }
        Ok(out)
    }
    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        Ok(self.by_relay.contains(nf))
    }
}

struct FakeModel {
    used: u32,
    fail: bool,
    calls: usize,
}

impl Upstream for FakeModel {
    fn complete(&mut self, prompt: &str, _max: u32) -> Result<ModelReply, String> {
        self.calls += 1;
        if self.fail {
            return Err("down".into());
        }
        Ok(ModelReply { text: format!("echo: {prompt}"), tokens_used: self.used })
    }
}

type TestRelay<S> = Relay<S, FakeChain, FakeModel>;

struct Setup {
    credit_sk: SecretKey,
    credit_pk: [u8; G2_LEN],
}

fn setup() -> Setup {
    let credit_sk = keygen(&mut OsRng);
    let credit_pk = credit_sk.public_key();
    Setup { credit_sk, credit_pk }
}

fn config(credit_pk: [u8; G2_LEN]) -> Config {
    Config {
        mint: MINT.into(),
        relay: RELAY.into(),
        mint_dst: MINT_DST.to_vec(),
        credit_key: credit_pk,
        tokens_per_credit: Q,
        max_tokens_per_request: 100,
    }
}

fn relay_with<S: Store>(store: S, s: &Setup, chain: FakeChain, key: SecretKey) -> TestRelay<S> {
    Relay::new(store, chain, FakeModel { used: 10, fail: false, calls: 0 }, config(s.credit_pk), key)
}

fn relay(s: &Setup) -> TestRelay<MemoryStore> {
    relay_with(MemoryStore::default(), s, FakeChain::default(), keygen(&mut OsRng))
}

fn credit(s: &Setup, denom: u8) -> (Token, SigningKey) {
    let p = PendingToken::new(&mut OsRng, denom, MINT_DST).unwrap();
    let sp = sign_blinded(&s.credit_sk, &p.blinded).unwrap();
    p.finish(&sp, &s.credit_pk).unwrap()
}

struct Wallet {
    xs: Vec<[u8; 32]>,
    factors: Vec<BlindingFactor>,
    blinded: Vec<String>,
}

fn wallet(dst: &[u8]) -> Wallet {
    let mut w = Wallet { xs: vec![], factors: vec![], blinded: vec![] };
    for _ in 0..Q {
        let mut x = [0u8; 32];
        OsRng.fill_bytes(&mut x);
        let (r, b) = blind(&x, dst, &mut OsRng);
        w.xs.push(x);
        w.factors.push(r);
        w.blinded.push(hex(&b));
    }
    w
}

fn exchange_body(t: &Token, owner: &SigningKey, blinded: &[String]) -> Value {
    let d = claim_digest(MINT, RELAY, &t.nullifier());
    json!({"token": hex(&t.to_bytes()), "owner_sig": hex(&sign_digest(owner, &d)), "blinded": blinded})
}

/// Runs a whole exchange and returns usable request tokens.
fn request_tokens<S: Store>(r: &mut TestRelay<S>, s: &Setup) -> Vec<String> {
    let (t, owner) = credit(s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    assert_eq!(r.exchange(&body).0, 202);
    r.flush().unwrap();
    let (status, reply) = r.exchange(&body);
    assert_eq!(status, 200, "{reply}");
    let pk = r.request_public_key();
    let dst = r.request_dst().to_vec();
    reply["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, sig)| {
            let sp: [u8; G1_LEN] = unhex(sig.as_str().unwrap()).try_into().unwrap();
            let unblinded = unblind(&sp, &w.factors[i]).unwrap();
            assert!(verify(&pk, &w.xs[i], &dst, &unblinded));
            let mut bytes = w.xs[i].to_vec();
            bytes.extend_from_slice(&unblinded);
            hex(&bytes)
        })
        .collect()
}

#[test]
fn exchange_then_chat() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    assert_eq!(tokens.len(), Q);
    let (status, reply) = r.chat(&json!({"token": tokens[0], "prompt": "bonjour"}));
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["mode"], "mock");
    assert_eq!(reply["reply"], "echo: bonjour");
}

#[test]
fn nothing_is_signed_before_the_chain_confirms() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    let (status, reply) = r.exchange(&body);
    assert_eq!(status, 202);
    assert!(reply.get("signatures").is_none());
    assert_eq!(r.exchange(&body).0, 202, "still pending");
    assert_eq!(r.chain.calls, 0);
}

#[test]
fn claim_refused_on_chain_signs_nothing() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.chain.spent.insert(t.nullifier()); // the owner redeemed it on chain in the meantime
    assert_eq!(r.flush().unwrap(), 0);
    let (status, reply) = r.exchange(&body);
    assert_eq!(status, 409);
    assert!(reply.get("signatures").is_none());
}

#[test]
fn replay_is_idempotent_and_other_points_are_refused() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.flush().unwrap();
    let first = r.exchange(&body);
    assert_eq!(first, r.exchange(&body), "same request, same answer");
    assert_eq!(r.chain.calls, 1);

    let other = wallet(r.request_dst());
    let (status, _) = r.exchange(&exchange_body(&t, &owner, &other.blinded));
    assert_eq!(status, 409, "a credit cannot buy a second set of tokens");
}

#[test]
fn other_points_are_refused_while_pending() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    r.exchange(&exchange_body(&t, &owner, &w.blinded));
    let other = wallet(r.request_dst());
    assert_eq!(r.exchange(&exchange_body(&t, &owner, &other.blinded)).0, 409);
}

#[test]
fn exchange_refusals() {
    let s = setup();
    let mut r = relay(&s);
    let dst = r.request_dst().to_vec();
    let (t, owner) = credit(&s, 0);
    let w = wallet(&dst);

    let (high, high_owner) = credit(&s, 1);
    assert_eq!(r.exchange(&exchange_body(&high, &high_owner, &w.blinded)).0, 400, "wrong tier");

    let other = setup();
    let (forged, forged_owner) = credit(&other, 0);
    assert_eq!(r.exchange(&exchange_body(&forged, &forged_owner, &w.blinded)).0, 400, "token from another key");

    let thief = SigningKey::generate(&mut OsRng);
    assert_eq!(r.exchange(&exchange_body(&t, &thief, &w.blinded)).0, 400, "not the owner");

    assert_eq!(r.exchange(&exchange_body(&t, &owner, &w.blinded[..2])).0, 400, "too few points");

    let mut inf = [0u8; G1_LEN];
    inf[0] = 0xc0;
    let mut bad = w.blinded.clone();
    bad[1] = hex(&inf);
    assert_eq!(r.exchange(&exchange_body(&t, &owner, &bad)).0, 400, "invalid point");

    r.chain.spent.insert(t.nullifier());
    assert_eq!(r.exchange(&exchange_body(&t, &owner, &w.blinded)).0, 409, "already spent");
    assert_eq!(r.chain.calls, 0);
    assert_eq!(r.exchange(&json!({"token": "zz"})).0, 400);
}

#[test]
fn request_token_works_once() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 200);
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "b"})).0, 409);
    assert_eq!(r.upstream.calls, 1, "the second attempt never reaches the model");
}

#[test]
fn forged_request_tokens_are_refused() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    let mut tampered = unhex(&tokens[0]);
    tampered[3] ^= 1;
    assert_eq!(r.chat(&json!({"token": hex(&tampered), "prompt": "a"})).0, 401);

    let other_key = keygen(&mut OsRng);
    let x = [9u8; 32];
    let sig = sign_blinded(&other_key, &request_message_point(&x, r.request_dst())).unwrap();
    let mut forged = x.to_vec();
    forged.extend_from_slice(&sig);
    assert_eq!(r.chat(&json!({"token": hex(&forged), "prompt": "a"})).0, 401);

    assert_eq!(r.chat(&json!({"token": "abcd", "prompt": "a"})).0, 400);
    assert_eq!(r.chat(&json!({"prompt": "a"})).0, 400);
    assert_eq!(r.upstream.calls, 0);
}

#[test]
fn a_reply_over_budget_is_withheld_and_the_token_is_spent() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    r.upstream.used = 101;
    let (status, reply) = r.chat(&json!({"token": tokens[0], "prompt": "a"}));
    assert_eq!(status, 402);
    assert!(reply.get("reply").is_none());
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 409);
}

#[test]
fn a_model_failure_returns_an_error() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    r.upstream.fail = true;
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 502);
}

#[test]
fn oversized_prompt_does_not_consume_the_token() {
    let s = setup();
    let mut r = relay(&s);
    let tokens = request_tokens(&mut r, &s);
    let long = "x".repeat(MAX_PROMPT_BYTES + 1);
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": long})).0, 413);
    assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 200);
}

#[test]
fn routing() {
    let s = setup();
    let mut r = relay(&s);
    assert_eq!(r.handle("/nothing", "{}").0, 404);
    assert_eq!(r.handle("/chat", "not json").0, 400);
    assert_eq!(r.handle("/chat", "{}").0, 400);
}

#[test]
fn a_failed_flush_keeps_the_credit_for_the_next_one() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.chain.fail = true;
    assert!(r.flush().is_err());
    assert_eq!(r.exchange(&body).0, 202);
    r.chain.fail = false;
    assert_eq!(r.flush().unwrap(), 1);
    assert_eq!(r.exchange(&body).0, 200);
}

#[test]
fn a_lost_reply_does_not_cost_the_user_a_credit() {
    let s = setup();
    let mut r = relay(&s);
    let (t, owner) = credit(&s, 0);
    let w = wallet(r.request_dst());
    let body = exchange_body(&t, &owner, &w.blinded);
    r.exchange(&body);
    r.chain.lose_reply = true;
    assert!(r.flush().is_err());
    r.chain.lose_reply = false;
    r.flush().unwrap();
    assert_eq!(r.exchange(&body).0, 200, "the claim landed, so the tokens are owed");
    assert_eq!(r.chain.calls, 1, "and it is not sent twice");
}

#[test]
fn batches_are_bounded() {
    let s = setup();
    let mut r = relay(&s);
    for _ in 0..(MAX_BATCH + 2) {
        let (t, owner) = credit(&s, 0);
        let w = wallet(r.request_dst());
        r.exchange(&exchange_body(&t, &owner, &w.blinded));
    }
    assert_eq!(r.flush().unwrap(), MAX_BATCH);
    assert_eq!(r.flush().unwrap(), 2);
}

#[test]
fn crash_after_the_chain_accepted_recovers_the_tokens() {
    let s = setup();
    let path = std::env::temp_dir().join(format!("ona-relay-{}-a.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key_bytes = keygen(&mut OsRng).to_bytes();
    let (t, owner) = credit(&s, 0);
    let dst = request_dst(RELAY);
    let w = wallet(&dst);
    let body = exchange_body(&t, &owner, &w.blinded);

    let chain = {
        let mut r = relay_with(FileStore::open(&path).unwrap(), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        r.exchange(&body);
        r.chain.lose_reply = true;
        assert!(r.flush().is_err(), "the crash happens during the chain call");
        let mut c = FakeChain::default();
        c.spent = r.chain.spent.clone();
        c.by_relay = r.chain.by_relay.clone();
        c
    };

    let mut r = relay_with(FileStore::open(&path).unwrap(), &s, chain, SecretKey::from_bytes(&key_bytes).unwrap());
    assert_eq!(r.exchange(&body).0, 202, "state survived the restart");
    assert_eq!(r.recover().unwrap(), 1);
    let (status, reply) = r.exchange(&body);
    assert_eq!(status, 200, "{reply}");
    assert_eq!(r.chain.calls, 0, "no second claim on chain");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn crash_when_someone_else_spent_it_signs_nothing() {
    let s = setup();
    let path = std::env::temp_dir().join(format!("ona-relay-{}-b.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key_bytes = keygen(&mut OsRng).to_bytes();
    let (t, owner) = credit(&s, 0);
    let dst = request_dst(RELAY);
    let w = wallet(&dst);
    let body = exchange_body(&t, &owner, &w.blinded);
    {
        let mut r = relay_with(FileStore::open(&path).unwrap(), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        r.exchange(&body);
        r.chain.fail = true;
        let _ = r.flush();
    }
    let mut chain = FakeChain::default();
    chain.spent.insert(t.nullifier());
    let mut r = relay_with(FileStore::open(&path).unwrap(), &s, chain, SecretKey::from_bytes(&key_bytes).unwrap());
    assert_eq!(r.recover().unwrap(), 1);
    assert_eq!(r.exchange(&body).0, 409);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn used_request_tokens_survive_a_restart() {
    let s = setup();
    let path = std::env::temp_dir().join(format!("ona-relay-{}-c.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key_bytes = keygen(&mut OsRng).to_bytes();
    let token = {
        let mut r = relay_with(FileStore::open(&path).unwrap(), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
        let tokens = request_tokens(&mut r, &s);
        assert_eq!(r.chat(&json!({"token": tokens[0], "prompt": "a"})).0, 200);
        tokens[0].clone()
    };
    let mut r = relay_with(FileStore::open(&path).unwrap(), &s, FakeChain::default(), SecretKey::from_bytes(&key_bytes).unwrap());
    assert_eq!(r.chat(&json!({"token": token, "prompt": "a"})).0, 409);
    assert_eq!(r.upstream.calls, 0);
    std::fs::remove_file(&path).unwrap();
}
