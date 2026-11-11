//! The pool on the mocked NEAR VM, which runs the real BLS12-381 and ed25519 host functions. Notes are made
//! with `ona-token` (blst), and every digest is recomputed here from the SPEC with `sha2`, so both sides are
//! cross-checked. Vault calls are only inspected as receipts: no staking pool runs here.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ed25519_dalek::{SigningKey, VerifyingKey};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::mock::MockAction;
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{env, testing_env, AccountId, Gas, NearToken, PromiseResult};
use ona_pool::*;
use ona_token::{blind, keygen, sign_blinded, sign_digest, unblind, PendingToken, SecretKey, Token, G2_LEN};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MILLI: u128 = NEAR / 1_000;
const NETWORK: &str = "sandbox";
/// Cash notes of 0.1, 1 and 10 NEAR.
const CASH: [u128; 3] = [NEAR / 10, NEAR, 10 * NEAR];
/// Share notes of 0.1 and 1 NEAR at the initial price.
const SHARES: [u128; 2] = [100_000, 1_000_000];
/// Added to each deposit, so the record's storage never eats into the amount the test needs.
const PAD: u128 = NEAR / 100;
/// Attached to each exit request: more than its storage fee.
const REQUEST_FEE: u128 = NEAR / 100;
const ADMIN_SECS: u64 = 7 * 86_400;
const ADMIN_NS: u64 = ADMIN_SECS * 1_000_000_000;
const FAR: u64 = u64::MAX / 2;
/// The standard position: one 10-NEAR cash note entered as nine notes of 0.1 NEAR and nine of 1.
const POSITION: [(u8, u64); 2] = [(0, 9), (1, 9)];
const IN_POSITION: u128 = 99 * NEAR / 10;
/// What a 1-NEAR share note at the initial price leaves as: nine cash notes of 0.1.
const ONE_TO_CASH: [(u8, u64); 1] = [(0, 9)];

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn contract() -> AccountId {
    acc("pool.test")
}
fn guardian() -> AccountId {
    acc("guardian.test")
}
fn agent() -> AccountId {
    acc("agent.test")
}
fn alice() -> AccountId {
    acc("alice.test")
}
fn bob() -> AccountId {
    acc("bob.test")
}
fn mallory() -> AccountId {
    acc("mallory.test")
}
fn staking(i: u32) -> AccountId {
    acc(&format!("validator{i}.test"))
}
fn b64(b: &[u8]) -> Base64VecU8 {
    Base64VecU8(b.to_vec())
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn panic_text(e: Box<dyn std::any::Any + Send>) -> String {
    e.downcast_ref::<String>()
        .cloned()
        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn context(pred: &AccountId, balance: u128, storage: u64, now: u64) {
    context_paying(pred, 0, balance, storage, now);
}

fn context_paying(pred: &AccountId, attached: u128, balance: u128, storage: u64, now: u64) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(contract())
        .predecessor_account_id(pred.clone())
        .signer_account_id(pred.clone())
        .attached_deposit(NearToken::from_yoctonear(attached))
        .account_balance(NearToken::from_yoctonear(balance))
        .storage_usage(storage)
        .block_timestamp(now)
        .prepaid_gas(Gas::from_tgas(300))
        .build());
}

// ---- digests, written from the SPEC independently of the contract ----

struct Note {
    token: Token,
    owner: SigningKey,
    /// `None` for a cash note.
    vault: Option<u32>,
}

fn nf(n: &Note) -> [u8; 32] {
    let t = &n.token;
    match n.vault {
        None => sha(&[b"ONA-POOL-CASH-NF-V1", &[t.denom_id], &t.pk, &t.nonce]),
        Some(v) => sha(&[b"ONA-POOL-NF-V1", &v.to_le_bytes(), &[t.denom_id], &t.pk, &t.nonce]),
    }
}

fn outs_bytes(list: &[(u8, u64)]) -> Vec<u8> {
    let mut d = (list.len() as u32).to_le_bytes().to_vec();
    for (tier, count) in list {
        d.push(*tier);
        d.extend_from_slice(&count.to_le_bytes());
    }
    d
}

fn exit_digest(n: &Note, to: &AccountId, min: u128, expires: u64) -> [u8; 32] {
    let c = sha(&[contract().as_bytes()]);
    let t = sha(&[to.as_bytes()]);
    match n.vault {
        None => sha(&[b"ONA-POOL-CASH-EXIT-V1", &c, &nf(n), &t, &expires.to_le_bytes()]),
        Some(v) => sha(&[
            b"ONA-POOL-EXIT-V2",
            &c,
            &v.to_le_bytes(),
            &nf(n),
            &t,
            &min.to_le_bytes(),
            &expires.to_le_bytes(),
        ]),
    }
}

fn enter_digest_spec(n: &Note, vault: u32, list: &[(u8, u64)], expires: u64) -> [u8; 32] {
    let c = sha(&[contract().as_bytes()]);
    sha(&[b"ONA-POOL-ENTER-V1", &c, &nf(n), &vault.to_le_bytes(), &outs_bytes(list), &expires.to_le_bytes()])
}

fn leave_digest_spec(n: &Note, list: &[(u8, u64)], expires: u64) -> [u8; 32] {
    let c = sha(&[contract().as_bytes()]);
    let v = n.vault.unwrap();
    sha(&[b"ONA-POOL-LEAVE-V1", &c, &v.to_le_bytes(), &nf(n), &outs_bytes(list), &expires.to_le_bytes()])
}

fn input(n: &Note) -> NoteInput {
    NoteInput { tier: n.token.denom_id, pk: b64(&n.token.pk), nonce: b64(&n.token.nonce), sig: b64(&n.token.sig) }
}

fn note_json(n: &Note) -> Value {
    json!({"tier": n.token.denom_id, "pk": n.token.pk.to_vec(), "nonce": n.token.nonce.to_vec(), "sig": n.token.sig.to_vec()})
}

fn signed(n: &Note, digest: [u8; 32]) -> Base64VecU8 {
    b64(&sign_digest(&n.owner, &digest))
}

fn outs(list: &[(u8, u64)]) -> Vec<NoteOut> {
    list.iter().map(|(tier, count)| NoteOut { tier: *tier, count: *count }).collect()
}

#[derive(Debug, Clone)]
struct Call {
    to: AccountId,
    method: String,
    args: String,
    deposit: u128,
}

struct H {
    pool: Pool,
    balance: u128,
    storage: u64,
    now: u64,
    keys: Vec<Vec<SecretKey>>,
    pks: Vec<Vec<[u8; G2_LEN]>>,
    cash_keys: Vec<SecretKey>,
    cash_pks: Vec<[u8; G2_LEN]>,
    transfers: Vec<(AccountId, u128)>,
    calls: Vec<Call>,
    logs: Vec<String>,
    /// The public methods the helpers called, with the arguments they passed.
    public: Vec<(String, Value)>,
    /// What each vault's staking pool holds for the pool, staked and already unstaked. With `strict`, it
    /// refuses to unstake more than is staked or to withdraw more than is unstaked, as the standard staking
    /// pool is expected to (not verified); otherwise it accepts any amount, as the older tests assume.
    staked: Vec<u128>,
    unstaked: Vec<u128>,
    strict: bool,
    /// With `strict`, when the unstaked funds of each vault can be withdrawn. Every `unstake` pushes it back
    /// for all of them, as the standard staking pool is expected to (not verified).
    unlock_at: Vec<u64>,
}

/// How long the strict mock keeps unstaked funds locked after an `unstake`: a stand-in for a few epochs.
const MOCK_LOCK_NS: u64 = 36 * HOUR_NS;

fn new_pool(
    escape: Option<u64>,
    admin: Option<u64>,
    cash_pks: &[[u8; G2_LEN]],
    cap: u128,
    rate: Option<u16>,
    min_live: u64,
) -> Pool {
    let tiers = cash_pks.iter().zip(CASH).map(|(pk, v)| CashTierInit { value: U128(v), pk_g2: b64(pk) }).collect();
    Pool::new(guardian(), agent(), NETWORK.into(), escape, admin, tiers, U128(cap), rate, min_live)
}

fn fresh_keys() -> Vec<[u8; G2_LEN]> {
    (0..3).map(|_| keygen(&mut OsRng).public_key()).collect()
}

fn refused_init(f: impl FnOnce() -> Pool) -> String {
    context(&acc("deployer.test"), NEAR, 0, 0);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(hook);
    panic_text(r.err().expect("the pool should have been refused"))
}

impl H {
    fn build(escape_secs: Option<u64>, max_assets: u128, hourly: u128, cash_cap: u128, min_live: u64) -> Self {
        let now = 1_000 * HOUR_NS;
        let balance = 5 * NEAR;
        context(&acc("deployer.test"), balance, 0, now);
        let cash_keys: Vec<SecretKey> = (0..3).map(|_| keygen(&mut OsRng)).collect();
        let cash_pks: Vec<[u8; G2_LEN]> = cash_keys.iter().map(|k| k.public_key()).collect();
        let pool = new_pool(escape_secs, Some(ADMIN_SECS), &cash_pks, cash_cap, None, min_live);
        let mut h = Self {
            pool,
            balance,
            storage: env::storage_usage(),
            now,
            keys: Vec::new(),
            pks: Vec::new(),
            cash_keys,
            cash_pks,
            transfers: Vec::new(),
            calls: Vec::new(),
            logs: Vec::new(),
            public: Vec::new(),
            staked: vec![0; MAX_VAULTS as usize],
            unstaked: vec![0; MAX_VAULTS as usize],
            strict: false,
            unlock_at: vec![0; MAX_VAULTS as usize],
        };
        h.add_vault(max_assets, hourly);
        h.add_vault(max_assets, hourly);
        // The listed vaults take effect, then the agent shows it is active.
        h.now += ADMIN_NS;
        h.sync(0, 0);
        h.calls.clear();
        h
    }

    fn with(escape_secs: Option<u64>, max_assets: u128, hourly: u128) -> Self {
        Self::build(escape_secs, max_assets, hourly, 1_000 * NEAR, 1)
    }

    fn new() -> Self {
        Self::with(None, 1_000 * NEAR, 1_000 * NEAR)
    }

    fn add_vault(&mut self, max_assets: u128, hourly: u128) -> u32 {
        let keys: Vec<SecretKey> = (0..2).map(|_| keygen(&mut OsRng)).collect();
        let pks: Vec<[u8; G2_LEN]> = keys.iter().map(|k| k.public_key()).collect();
        let tiers = pks.iter().zip(SHARES).map(|(pk, s)| TierInit { shares: U128(s), pk_g2: b64(pk) }).collect();
        let id = self.pks.len() as u32;
        let got = self.call(&guardian(), |p| {
            p.add_vault("staking".into(), staking(id), b64(&[7; 32]), tiers, U128(max_assets), U128(hourly))
        });
        assert_eq!(got, id);
        self.keys.push(keys);
        self.pks.push(pks);
        id
    }

    /// Runs one method, applies its outgoing transfers and calls, keeps its logs, and checks that the pool
    /// still covers everything it holds.
    fn call<R>(&mut self, pred: &AccountId, f: impl FnOnce(&mut Pool) -> R) -> R {
        self.call_paying(pred, 0, f)
    }

    fn call_paying<R>(&mut self, pred: &AccountId, attached: u128, f: impl FnOnce(&mut Pool) -> R) -> R {
        self.balance += attached;
        context_paying(pred, attached, self.balance, self.storage, self.now);
        let r = f(&mut self.pool);
        self.storage = env::storage_usage();
        self.logs.extend(get_logs());
        self.collect();
        assert!(self.status().solvent, "the pool no longer covers what it holds");
        r
    }

    fn collect(&mut self) {
        for receipt in get_created_receipts() {
            for action in receipt.actions {
                match action {
                    MockAction::Transfer { deposit, .. } => {
                        self.balance -= deposit.as_yoctonear();
                        self.transfers.push((receipt.receiver_id.clone(), deposit.as_yoctonear()));
                    }
                    MockAction::FunctionCallWeight { method_name, args, attached_deposit, .. } => {
                        self.balance -= attached_deposit.as_yoctonear();
                        self.calls.push(Call {
                            to: receipt.receiver_id.clone(),
                            method: String::from_utf8(method_name).unwrap(),
                            args: String::from_utf8(args).unwrap(),
                            deposit: attached_deposit.as_yoctonear(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    fn refused(&mut self, pred: &AccountId, f: impl FnOnce(&mut Pool)) -> String {
        self.refused_paying(pred, 0, f)
    }

    fn refused_paying(&mut self, pred: &AccountId, attached: u128, f: impl FnOnce(&mut Pool)) -> String {
        context_paying(pred, attached, self.balance + attached, self.storage, self.now);
        let pool = &mut self.pool;
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = catch_unwind(AssertUnwindSafe(|| f(pool)));
        std::panic::set_hook(hook);
        panic_text(result.expect_err("the call should have been refused"))
    }

    /// Delivers the result of a vault call, or of a payout, to its callback.
    fn callback(&mut self, result: PromiseResult, f: impl FnOnce(&mut Pool)) {
        self.callback_with(vec![result], f);
    }

    /// Delivers several joined results to one callback.
    fn callback_with(&mut self, results: Vec<PromiseResult>, f: impl FnOnce(&mut Pool)) {
        let ctx = VMContextBuilder::new()
            .current_account_id(contract())
            .predecessor_account_id(contract())
            .account_balance(NearToken::from_yoctonear(self.balance))
            .storage_usage(self.storage)
            .block_timestamp(self.now)
            .prepaid_gas(Gas::from_tgas(100))
            .build();
        testing_env!(
            ctx,
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            results
        );
        f(&mut self.pool);
        self.storage = env::storage_usage();
        self.logs.extend(get_logs());
        self.collect();
    }

    fn view<R>(&mut self, f: impl FnOnce(&Pool) -> R) -> R {
        context(&alice(), self.balance, self.storage, self.now);
        f(&self.pool)
    }

    fn status(&mut self) -> ReserveStatus {
        self.view(|p| p.reserve_status())
    }

    fn vault(&mut self, id: u32) -> VaultView {
        self.view(|p| p.get_vault(id))
    }

    fn cash_view(&mut self) -> CashView {
        self.view(|p| p.get_cash())
    }

    fn holder(&mut self, a: &AccountId) -> HolderView {
        self.view(|p| p.get_holder(a.clone()))
    }

    fn byte_cost(&mut self) -> u128 {
        self.view(|_| env::storage_byte_cost().as_yoctonear())
    }

    /// What a request keeps for good from its fee: the note's mark.
    fn mark(&mut self) -> u128 {
        MARK_BYTES * self.byte_cost()
    }

    /// A plain transfer to the pool, with no method call.
    fn plain_transfer(&mut self, amount: u128) {
        self.balance += amount;
    }

    fn deposit(&mut self, who: &AccountId, amount: u128) {
        self.public.push(("deposit".into(), json!({})));
        self.call_paying(who, amount + PAD, |p| p.deposit());
    }

    /// A cash note signed blind by the agent's key for `tier`, whether issued or not.
    fn cash_note(&self, tier: u8) -> Note {
        let dst = cash_dst(NETWORK, contract().as_str()).into_bytes();
        let pending = PendingToken::new(&mut OsRng, tier, &dst).unwrap();
        let sig = sign_blinded(&self.cash_keys[usize::from(tier)], &pending.blinded).unwrap();
        let (token, owner) = pending.finish(&sig, &self.cash_pks[usize::from(tier)]).unwrap();
        Note { token, owner, vault: None }
    }

    /// A cash note whose owner key is `owner`, as a careless wallet would make.
    fn cash_note_owned_by(&self, tier: u8, owner: &SigningKey) -> Note {
        let pk = owner.verifying_key().to_bytes();
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let mut msg = vec![tier];
        msg.extend_from_slice(&pk);
        msg.extend_from_slice(&nonce);
        let dst = cash_dst(NETWORK, contract().as_str()).into_bytes();
        let (r, b) = blind(&msg, &dst, &mut OsRng);
        let sig = unblind(&sign_blinded(&self.cash_keys[usize::from(tier)], &b).unwrap(), &r).unwrap();
        Note { token: Token { denom_id: tier, pk, nonce, sig }, owner: owner.clone(), vault: None }
    }

    fn share_note(&self, vault: u32, tier: u8) -> Note {
        let dst = note_dst(NETWORK, contract().as_str(), vault).into_bytes();
        let pending = PendingToken::new(&mut OsRng, tier, &dst).unwrap();
        let sig = sign_blinded(&self.keys[vault as usize][usize::from(tier)], &pending.blinded).unwrap();
        let (token, owner) = pending.finish(&sig, &self.pks[vault as usize][usize::from(tier)]).unwrap();
        Note { token, owner, vault: Some(vault) }
    }

    /// `who` deposits, the agent issues `count` cash notes of `tier` for it and signs them.
    fn cash(&mut self, who: &AccountId, tier: u8, count: u64) -> Vec<Note> {
        self.deposit(who, CASH[usize::from(tier)] * u128::from(count));
        let w = who.clone();
        self.public.push(("issue_cash".into(), json!({"account": who.as_str(), "tier": tier, "count": count})));
        self.call(&agent(), move |p| p.issue_cash(w, tier, count));
        (0..count).map(|_| self.cash_note(tier)).collect()
    }

    /// A cash note becomes share notes of `vault`.
    fn enter(&mut self, n: &Note, vault: u32, list: &[(u8, u64)]) -> Vec<Note> {
        let (note, sig, o) = (input(n), signed(n, enter_digest_spec(n, vault, list, FAR)), outs(list));
        self.public.push((
            "enter".into(),
            json!({"vault_id": vault, "note": note_json(n), "owner_sig": sig.0, "outputs": list, "expires_at": FAR}),
        ));
        self.call(&agent(), move |p| p.enter(vault, note, sig, o, FAR));
        list.iter().flat_map(|(tier, count)| (0..*count).map(|_| self.share_note(vault, *tier))).collect()
    }

    /// `who` holds 9.9 NEAR of `vault`: nine notes of 0.1, then nine of 1.
    fn position(&mut self, vault: u32, who: &AccountId) -> Vec<Note> {
        let c = self.cash(who, 2, 1);
        self.enter(&c[0], vault, &POSITION)
    }

    /// A share note becomes cash notes.
    fn leave(&mut self, n: &Note, list: &[(u8, u64)]) -> Vec<Note> {
        let vault = n.vault.unwrap();
        let (note, sig, o) = (input(n), signed(n, leave_digest_spec(n, list, FAR)), outs(list));
        self.public.push((
            "leave".into(),
            json!({"vault_id": vault, "note": note_json(n), "owner_sig": sig.0, "outputs": list, "expires_at": FAR}),
        ));
        self.call(&agent(), move |p| p.leave(vault, note, sig, o, FAR));
        list.iter().flat_map(|(tier, count)| (0..*count).map(|_| self.cash_note(*tier))).collect()
    }

    fn refused_leave(&mut self, n: &Note, list: &[(u8, u64)]) -> String {
        let vault = n.vault.unwrap();
        let (note, sig, o) = (input(n), signed(n, leave_digest_spec(n, list, FAR)), outs(list));
        self.refused(&agent(), move |p| p.leave(vault, note, sig, o, FAR))
    }

    fn refused_enter(&mut self, n: &Note, vault: u32, list: &[(u8, u64)]) -> String {
        let (note, sig, o) = (input(n), signed(n, enter_digest_spec(n, vault, list, FAR)), outs(list));
        self.refused(&agent(), move |p| p.enter(vault, note, sig, o, FAR))
    }

    /// Delivers the callback of the operation the vault is busy with.
    fn reply(&mut self, vault: u32, result: PromiseResult, f: impl FnOnce(&mut Pool, u64)) {
        let op = self.vault(vault).busy_op;
        self.callback(result, |p| f(p, op));
    }

    fn place(&mut self, vault: u32, amount: u128) {
        self.call(&agent(), |p| p.place(vault, U128(amount)));
        self.reply(vault, PromiseResult::Successful(vec![]), |p, op| p.on_place(vault, U128(amount), op));
        self.staked[vault as usize] += amount;
    }

    /// The target reports what it holds for the pool. A change shows up on the staked part (rewards or loss).
    fn sync_by(&mut self, who: &AccountId, vault: u32, total: u128) {
        self.call(who, |p| p.sync(vault));
        let reply = format!("\"{total}\"").into_bytes();
        self.reply(vault, PromiseResult::Successful(reply), |p, op| p.on_sync(vault, op));
        let v = vault as usize;
        self.staked[v] = total.saturating_sub(self.unstaked[v]);
    }

    /// The arguments of the last call this pool made to itself for `method`.
    fn self_call(&self, method: &str) -> Value {
        let c = self.calls.iter().rev().find(|c| c.to == contract() && c.method == method).expect("no such callback");
        serde_json::from_str(&c.args).unwrap()
    }

    /// The amount of the last call to the target for `method` made after `since` calls.
    fn target_call_after(&self, since: usize, method: &str) -> Option<u128> {
        self.calls[since..].iter().rev().find(|c| c.to != contract() && c.method == method).map(|c| {
            let args: Value = serde_json::from_str(&c.args).unwrap();
            args["amount"].as_str().unwrap().parse().unwrap()
        })
    }

    fn u128_reply(amount: u128) -> PromiseResult {
        PromiseResult::Successful(format!("\"{amount}\"").into_bytes())
    }

    /// What the staking pool answers to `get_account_staked_balance` / `get_account_unstaked_balance`.
    fn staked_reading(&mut self, vault: u32) -> u128 {
        if self.strict {
            self.staked[vault as usize]
        } else {
            self.vault(vault).placed.0
        }
    }

    fn unstaked_reading(&mut self, vault: u32) -> u128 {
        if self.strict {
            self.unstaked[vault as usize]
        } else {
            self.vault(vault).placed.0
        }
    }

    /// The staking pool runs an `unstake` of `amount`: true if it accepts.
    fn run_unstake(&mut self, vault: u32, amount: u128) -> bool {
        let v = vault as usize;
        if self.strict && amount > self.staked[v] {
            return false;
        }
        let moved = amount.min(self.staked[v]);
        self.staked[v] -= moved;
        self.unstaked[v] += moved;
        self.unlock_at[v] = self.now + MOCK_LOCK_NS;
        true
    }

    /// The staking pool runs a `withdraw` of `amount`: true if it accepts, and the money arrives.
    fn run_withdraw(&mut self, vault: u32, amount: u128) -> bool {
        let v = vault as usize;
        if self.strict && (amount > self.unstaked[v] || self.now < self.unlock_at[v]) {
            return false;
        }
        let from_unstaked = amount.min(self.unstaked[v]);
        self.unstaked[v] -= from_unstaked;
        self.staked[v] = self.staked[v].saturating_sub(amount - from_unstaked);
        self.balance += amount;
        true
    }

    fn outcome(ok: bool) -> PromiseResult {
        if ok {
            PromiseResult::Successful(vec![])
        } else {
            PromiseResult::Failed
        }
    }

    fn sync(&mut self, vault: u32, total: u128) {
        self.sync_by(&agent(), vault, total);
    }

    /// An `unstake`, run to the end against the staking pool mock. Returns whether the pool accepted it.
    fn unstake_by(&mut self, who: &AccountId, vault: u32, amount: Option<u128>) -> bool {
        let forced = *who != agent() || self.vault(vault).open;
        let since = self.calls.len();
        self.call(who, |p| p.unstake(vault, amount.map(U128)));
        let asked = if forced {
            let args = self.self_call("on_staked_read");
            let (op, target) = (args["op"].as_u64().unwrap(), args["amount"].as_str().unwrap().parse::<u128>().unwrap());
            let staked = self.staked_reading(vault);
            let unstaked = if self.strict { self.unstaked[vault as usize] } else { 0 };
            let mark = self.calls.len();
            let results = vec![Self::u128_reply(unstaked), Self::u128_reply(staked)];
            self.callback_with(results, |p| p.on_staked_read(vault, op, U128(target)));
            match self.target_call_after(mark, "unstake") {
                Some(a) => a,
                None => return false,
            }
        } else {
            self.target_call_after(since, "unstake").unwrap()
        };
        let ok = self.run_unstake(vault, asked);
        self.reply(vault, Self::outcome(ok), |p, op| p.on_unstake(vault, op, forced));
        ok
    }

    /// A `withdraw`, run to the end against the staking pool mock. Returns whether the pool accepted it.
    fn withdraw_by(&mut self, who: &AccountId, vault: u32, amount: Option<u128>) -> bool {
        let forced = *who != agent() || self.vault(vault).open;
        let since = self.calls.len();
        self.call(who, |p| p.withdraw(vault, amount.map(U128)));
        let asked = if forced {
            let args = self.self_call("on_unstaked_read");
            let (op, target) = (args["op"].as_u64().unwrap(), args["amount"].as_str().unwrap().parse::<u128>().unwrap());
            let unstaked = self.unstaked_reading(vault);
            let mark = self.calls.len();
            self.callback(Self::u128_reply(unstaked), |p| p.on_unstaked_read(vault, op, U128(target)));
            match self.target_call_after(mark, "withdraw") {
                Some(a) => a,
                None => return false,
            }
        } else {
            self.target_call_after(since, "withdraw").unwrap()
        };
        let ok = self.run_withdraw(vault, asked);
        self.reply(vault, Self::outcome(ok), |p, op| p.on_withdraw(vault, U128(asked), op));
        ok
    }

    fn withdraw(&mut self, vault: u32, amount: u128) {
        self.withdraw_by(&agent(), vault, Some(amount));
    }

    /// The last amount sent to a target for `method`.
    fn last_amount(&self, method: &str) -> String {
        self.calls.iter().rev().find(|c| c.method == method).map(|c| c.args.clone()).unwrap_or_default()
    }
}

fn pay(h: &mut H, n: &Note, to: &AccountId) {
    let (note, sig, to) = (input(n), signed(n, exit_digest(n, to, 0, FAR)), to.clone());
    h.public.push((
        "pay_exit".into(),
        json!({"note": note_json(n), "owner_sig": sig.0, "to": to.as_str(), "expires_at": FAR}),
    ));
    h.call(&agent(), move |p| p.pay_exit(note, sig, to, FAR));
}

fn refused_pay(h: &mut H, n: &Note, to: &AccountId) -> String {
    let (note, sig, to) = (input(n), signed(n, exit_digest(n, to, 0, FAR)), to.clone());
    h.refused(&agent(), move |p| p.pay_exit(note, sig, to, FAR))
}

fn request(h: &mut H, n: &Note, to: &AccountId) {
    let until = h.now + 25 * DAY_NS;
    request_until(h, n, to, until);
}

fn request_until(h: &mut H, n: &Note, to: &AccountId, expires: u64) {
    let (note, sig, to, vault) = (input(n), signed(n, exit_digest(n, to, 0, expires)), to.clone(), n.vault);
    h.call_paying(&to.clone(), REQUEST_FEE, move |p| p.request_exit(vault, note, sig, to, U128(0), expires));
}

fn escape(h: &mut H, by: &AccountId, n: &Note, to: &AccountId) {
    let (note, sig, to, vault) = (input(n), signed(n, exit_digest(n, to, 0, FAR)), to.clone(), n.vault);
    h.call(by, move |p| p.escape_exit(vault, note, sig, to, U128(0), FAR));
}

fn refused_escape(h: &mut H, by: &AccountId, n: &Note, to: &AccountId) -> String {
    let (note, sig, to, vault) = (input(n), signed(n, exit_digest(n, to, 0, FAR)), to.clone(), n.vault);
    h.refused(by, move |p| p.escape_exit(vault, note, sig, to, U128(0), FAR))
}

fn cancel(h: &mut H, n: &Note, by: &AccountId) {
    let (vault, id) = (n.vault, b64(&nf(n)));
    h.call(by, move |p| p.cancel_exit_request(vault, id));
}

// ---- the list of vaults ----

#[test]
fn only_the_guardian_lists_vaults_and_lending_is_not_built() {
    let mut h = H::new();
    let pk = keygen(&mut OsRng).public_key();
    let tiers = vec![TierInit { shares: U128(1), pk_g2: b64(&pk) }];
    let cases = [
        (agent(), "staking", 32usize, "only the guardian"),
        (guardian(), "lending", 32, "lending adapter not implemented"),
        (guardian(), "swap", 32, "unknown adapter"),
        (guardian(), "staking", 31, "bad code hash length"),
    ];
    for (who, kind, hash_len, refusal) in cases {
        let t = tiers.clone();
        let e = h.refused(&who, move |p| {
            p.add_vault(kind.into(), staking(9), b64(&vec![7; hash_len]), t, U128(NEAR), U128(1_000 * NEAR));
        });
        assert!(e.contains(refusal), "{e}");
    }
}

#[test]
fn a_target_serves_one_vault_only() {
    let mut h = H::new();
    let pk = keygen(&mut OsRng).public_key();
    let e = h.refused(&guardian(), move |p| {
        let tiers = vec![TierInit { shares: U128(SHARES[1]), pk_g2: b64(&pk) }];
        p.add_vault("staking".into(), staking(0), b64(&[7; 32]), tiers, U128(NEAR), U128(1_000 * NEAR));
    });
    assert!(e.contains("this target already serves a vault"), "{e}");
}

#[test]
fn a_key_serves_one_tier_of_one_vault_or_of_the_cash() {
    let mut h = H::new();
    for reused in [h.pks[0][0], h.cash_pks[0]] {
        let e = h.refused(&guardian(), move |p| {
            let tiers = vec![TierInit { shares: U128(1), pk_g2: b64(&reused) }];
            p.add_vault("staking".into(), staking(9), b64(&[7; 32]), tiers, U128(NEAR), U128(1_000 * NEAR));
        });
        assert!(e.contains("key already used"), "{e}");
    }
}

#[test]
fn the_hourly_cap_covers_two_of_the_largest_notes() {
    let mut h = H::new();
    let pk = keygen(&mut OsRng).public_key();
    let e = h.refused(&guardian(), move |p| {
        let tiers = vec![TierInit { shares: U128(SHARES[1]), pk_g2: b64(&pk) }];
        p.add_vault("staking".into(), staking(9), b64(&[7; 32]), tiers, U128(NEAR), U128(2 * NEAR - 1));
    });
    assert!(e.contains("the hourly cap must cover two of the largest notes"), "{e}");
    let keys = fresh_keys();
    let e = refused_init(move || new_pool(None, None, &keys, 20 * NEAR - 1, None, 1));
    assert!(e.contains("the hourly cap must cover two of the largest notes"), "{e}");
}

#[test]
fn the_pool_settings_are_bounded() {
    let (a, b, c, d, e) = (fresh_keys(), fresh_keys(), fresh_keys(), fresh_keys(), fresh_keys());
    assert!(refused_init(move || new_pool(Some(1), None, &a, 20 * NEAR, None, 1)).contains("escape delay"));
    assert!(refused_init(move || new_pool(None, Some(ADMIN_SECS - 1), &b, 20 * NEAR, None, 1)).contains("admin delay"));
    assert!(refused_init(move || new_pool(None, Some(31 * 86_400), &c, 20 * NEAR, None, 1)).contains("admin delay"));
    let r = refused_init(move || new_pool(None, None, &d, 20 * NEAR, Some(MAX_RATE_BPS + 1), 1));
    assert!(r.contains("rate too high"), "{r}");
    let r = refused_init(move || new_pool(None, None, &e, 20 * NEAR, None, 0));
    assert!(r.contains("min_live_notes must be at least 1"), "{r}");
    let small = keygen(&mut OsRng).public_key();
    let r = refused_init(move || {
        let tiers = vec![CashTierInit { value: U128(4 * MILLI), pk_g2: b64(&small) }];
        Pool::new(guardian(), agent(), NETWORK.into(), None, None, tiers, U128(NEAR), None, 1)
    });
    assert!(r.contains("worth more than its fees"), "{r}");
    let mut h = H::with(Some(600), 1_000 * NEAR, 1_000 * NEAR);
    assert_eq!(h.view(|p| p.get_config().escape_delay_ns), 600_000_000_000);
    assert_eq!(h.view(|p| p.get_config().max_rate_bps), DEFAULT_MAX_RATE_BPS);
}

#[test]
fn the_agent_calls_only_listed_vaults_and_only_their_methods() {
    let mut h = H::new();
    h.position(0, &alice());
    let e = h.refused(&agent(), |p| p.place(7, U128(NEAR)));
    assert!(e.contains("unknown vault"), "{e}");
    let e = h.refused(&alice(), |p| p.place(0, U128(NEAR)));
    assert!(e.contains("only the agent"), "{e}");

    h.place(0, 4 * NEAR);
    h.unstake_by(&agent(), 0, Some(NEAR));
    h.withdraw(0, NEAR);
    h.sync(0, 3 * NEAR);

    let external: Vec<&Call> = h.calls.iter().filter(|c| c.to != contract()).collect();
    assert!(external.iter().all(|c| c.to == staking(0)), "only the listed target is called");
    let methods: Vec<&str> = external.iter().map(|c| c.method.as_str()).collect();
    assert_eq!(methods, ["deposit_and_stake", "unstake", "withdraw", "get_account_total_balance"]);
    assert_eq!(external[0].deposit, 4 * NEAR);
    assert!(external[1..].iter().all(|c| c.deposit == 0), "only a placement carries money");
    assert_eq!(external[1].args, format!("{{\"amount\":\"{NEAR}\"}}"));
    assert_eq!(external[3].args, "{\"account_id\":\"pool.test\"}");
}

#[test]
fn a_vault_runs_one_operation_at_a_time() {
    let mut h = H::new();
    h.position(0, &alice());
    h.call(&agent(), |p| p.place(0, U128(NEAR)));
    let e = h.refused(&agent(), |p| p.sync(0));
    assert!(e.contains("still running"), "{e}");
    h.now += BUSY_TIMEOUT_NS;
    h.call(&agent(), |p| p.sync(0));
}

#[test]
fn a_failed_placement_returns_to_the_vaults_liquid_funds() {
    let mut h = H::new();
    h.position(0, &alice());
    h.call(&agent(), |p| p.place(0, U128(4 * NEAR)));
    h.balance += 4 * NEAR; // a failed call sends its deposit back
    h.reply(0, PromiseResult::Failed, |p, op| p.on_place(0, U128(4 * NEAR), op));
    let v = h.vault(0);
    assert_eq!((v.liquid.0, v.placed.0, v.busy), (IN_POSITION, 0, false));
}

// ---- deposits and cash ----

#[test]
fn cash_is_issued_only_from_the_accounts_own_deposits() {
    let mut h = H::new();
    h.plain_transfer(20 * NEAR);
    h.deposit(&alice(), NEAR);
    let e = h.refused(&agent(), |p| p.issue_cash(alice(), 1, 2));
    assert!(e.contains("more than this account's deposits not turned into cash"), "{e}");
    let e = h.refused(&agent(), |p| p.issue_cash(bob(), 0, 1));
    assert!(e.contains("not a depositor"), "{e}");
    let e = h.refused(&alice(), |p| p.issue_cash(alice(), 1, 1));
    assert!(e.contains("only the agent"), "{e}");
    h.call(&agent(), |p| p.issue_cash(alice(), 1, 1));
    assert_eq!(h.cash_view().liquid.0, NEAR);
    assert_eq!(h.holder(&alice()).issued.0, NEAR);
    let e = h.refused(&agent(), |p| p.issue_cash(alice(), 1, 1));
    assert!(e.contains("more than this account's deposits not turned into cash"), "{e}");
    let e = h.refused(&alice(), |p| p.deposit());
    assert!(e.contains("deposit too small"), "{e}");
}

#[test]
fn no_cash_is_issued_to_an_account_that_asked_for_a_refund() {
    let mut h = H::new();
    h.deposit(&alice(), 2 * NEAR);
    h.call(&alice(), |p| p.request_refund());
    let e = h.refused(&agent(), |p| p.issue_cash(alice(), 1, 1));
    assert!(e.contains("this account asked for a refund"), "{e}");
}

#[test]
fn a_deposit_pays_for_the_storage_of_its_record() {
    let mut h = H::new();
    let before = h.storage;
    h.deposit(&alice(), NEAR);
    let added = u128::from(h.storage - before);
    assert!(added > 0);
    let cost = added * h.byte_cost();
    assert_eq!(h.holder(&alice()).deposited.0, NEAR + PAD - cost, "the new record's storage comes off the deposit");
    h.deposit(&alice(), NEAR);
    assert_eq!(h.holder(&alice()).deposited.0, 2 * (NEAR + PAD) - cost, "a known depositor adds no storage");
}

#[test]
fn a_refund_pays_back_only_the_accounts_own_deposits_never_turned_into_cash() {
    // A newcomer whose own vault never grew must not take a share of someone else's fresh deposit.
    let mut h = H::new();
    h.position(0, &alice());
    h.place(0, IN_POSITION);
    h.sync(0, IN_POSITION + NEAR);
    let m = mallory();
    h.position(1, &m);
    h.call(&m, |p| p.request_refund());
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, IN_POSITION + NEAR);
    }
    h.deposit(&bob(), NEAR);
    let own = h.holder(&m).refundable.0;
    assert!(own < PAD, "only mallory's own leftover");
    let e = h.refused(&m, move |p| p.refund_deposit(U128(own + 1)));
    assert!(e.contains("more than this account's deposits not turned into cash"), "{e}");
    h.call(&m, move |p| p.refund_deposit(U128(own)));
    assert!(h.holder(&bob()).refundable.0 >= NEAR, "bob's deposit is untouched");
    h.call(&agent(), |p| p.issue_cash(bob(), 1, 1));
}

#[test]
fn a_depositor_takes_back_money_never_turned_into_cash_once_the_escape_opens() {
    let mut h = H::new();
    h.deposit(&alice(), 5 * NEAR);
    h.cash(&alice(), 1, 2);
    let e = h.refused(&alice(), |p| p.refund_deposit(U128(NEAR)));
    assert!(e.contains("the agent is still active"), "{e}");
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    let e = h.refused(&mallory(), |p| p.refund_deposit(U128(NEAR)));
    assert!(e.contains("not a depositor"), "{e}");
    let left = h.holder(&alice()).refundable.0;
    assert!(left >= 5 * NEAR && left < 5 * NEAR + 2 * PAD);
    h.transfers.clear();
    h.call(&alice(), move |p| p.refund_deposit(U128(left)));
    assert_eq!(h.transfers, vec![(alice(), left)]);
    assert_eq!(h.status().unassigned.0, 0);
}

#[test]
fn a_refund_request_opens_refunds_even_while_the_agent_syncs_daily() {
    let mut h = H::new();
    h.deposit(&alice(), 3 * NEAR);
    let e = h.refused(&mallory(), |p| p.request_refund());
    assert!(e.contains("not a depositor"), "{e}");
    h.call(&alice(), |p| p.request_refund());
    let e = h.refused(&alice(), |p| p.request_refund());
    assert!(e.contains("refund already requested"), "{e}");
    for _ in 0..6 {
        h.now += DAY_NS;
        h.sync(0, 0);
    }
    h.now += DAY_NS - 1;
    let e = h.refused(&alice(), |p| p.refund_deposit(U128(NEAR)));
    assert!(e.contains("the agent is still active"), "{e}");
    h.now += 1;
    assert!(!h.view(|p| p.escape_open()));
    h.call(&alice(), |p| p.refund_deposit(U128(3 * NEAR)));
}

// ---- the exit limit ----

#[test]
fn money_going_round_does_not_raise_the_exit_limit() {
    // 10 NEAR deposited and paid back twenty times over a year: the limit grows on the net balance, not on
    // the sum of deposits.
    let mut h = H::new();
    for _ in 0..20 {
        let c = h.cash(&alice(), 2, 1);
        pay(&mut h, &c[0], &alice());
        h.now += YEAR_NS / 20;
        h.sync(0, 0);
    }
    let me = h.holder(&alice());
    assert!(me.exit_limit.0 < NEAR, "only the small leftovers ever grew: {}", me.exit_limit.0);
    // So the agent cannot pay alice someone else's cash.
    let other = h.cash(&bob(), 2, 1);
    let e = refused_pay(&mut h, &other[0], &alice());
    assert!(e.contains("over this account's exit limit"), "{e}");
}

#[test]
fn the_exit_limit_grows_with_time_on_money_still_in_the_pool() {
    let mut h = H::new();
    h.cash(&alice(), 2, 1);
    let base = h.holder(&alice()).deposited.0;
    h.now += YEAR_NS;
    let limit = h.holder(&alice()).exit_limit.0;
    assert_eq!(limit, base + 2 * NEAR, "20 % a year on the 10 NEAR of cash, nothing on the leftover");
}

#[test]
fn money_never_turned_into_cash_earns_nothing() {
    // 100 NEAR parked for a year, then refunded: no limit is left to receive someone else's cash.
    let mut h = H::new();
    let m = mallory();
    h.deposit(&m, 100 * NEAR);
    h.call(&m, |p| p.request_refund());
    for _ in 0..365 {
        h.now += DAY_NS;
        h.sync(0, 0);
    }
    let left = h.holder(&m).refundable.0;
    h.call(&m, move |p| p.refund_deposit(U128(left)));
    assert_eq!(h.holder(&m).exit_limit.0, 0);
}

#[test]
fn the_exit_limit_ignores_share_prices() {
    // Rewards left on a few shares must not lift anyone's limit.
    let mut h = H::new();
    let x = acc("x.test");
    h.position(0, &x);
    h.place(0, IN_POSITION);
    let limit = h.holder(&x).exit_limit.0;
    h.sync(0, IN_POSITION + 5 * NEAR);
    assert!(h.vault(0).share_price.0 > INITIAL_PRICE);
    assert_eq!(h.holder(&x).exit_limit.0, limit, "a price does not move a limit");
    let extra = h.cash(&bob(), 2, 2);
    pay(&mut h, &extra[0], &x); // up to its own deposit
    let e = refused_pay(&mut h, &extra[1], &x);
    assert!(e.contains("over this account's exit limit"), "{e}");
}

#[test]
fn the_exit_limit_is_rounded_up() {
    let mut h = H::new();
    h.cash(&alice(), 1, 1);
    let base = h.holder(&alice()).deposited.0;
    h.now += 1;
    let year = 10_000 * u128::from(YEAR_NS);
    let exact = NEAR * u128::from(DEFAULT_MAX_RATE_BPS);
    assert_ne!(exact % year, 0);
    assert_eq!(h.holder(&alice()).exit_limit.0, base + exact / year + 1, "the growth is rounded up, not down");
}

// ---- entering and leaving ----

#[test]
fn an_entry_turns_a_cash_note_into_share_notes_at_the_vault_price() {
    let mut h = H::new();
    let c = h.cash(&alice(), 2, 1);
    let shares = h.enter(&c[0], 0, &POSITION);
    let v = h.vault(0);
    assert_eq!((v.liquid.0, v.total_shares.0, v.share_price.0), (IN_POSITION, 9_900_000, INITIAL_PRICE));
    assert_eq!((v.tiers[0].issued, v.tiers[1].issued), (9, 9));
    assert_eq!(h.cash_view().liquid.0, 10 * NEAR - IN_POSITION - NOTE_STORAGE_FEE);
    assert_eq!(h.cash_view().outstanding.0, 0);
    let e = h.refused_enter(&c[0], 0, &POSITION);
    assert!(e.contains("note already spent"), "{e}");
    assert_eq!(shares.len(), 18);
}

#[test]
fn an_entry_or_a_leave_follows_exactly_what_the_owner_signed() {
    let mut h = H::new();
    let c = h.cash(&alice(), 2, 1);
    let sig = signed(&c[0], enter_digest_spec(&c[0], 0, &POSITION, FAR));
    for (vault, list) in [(1u32, POSITION.to_vec()), (0, vec![(0, 9), (1, 8)])] {
        let (note, s) = (input(&c[0]), sig.clone());
        let e = h.refused(&agent(), move |p| p.enter(vault, note, s, outs(&list), FAR));
        assert!(e.contains("bad owner signature"), "{e}");
    }
    let e = h.refused_enter(&c[0], 0, &[(1, 8)]);
    assert!(e.contains("too much left over"), "{e}");
    let e = h.refused_enter(&c[0], 0, &[(1, 10)]);
    assert!(e.contains("worth more than the note"), "{e}");
}

#[test]
fn an_owner_signature_expires() {
    let mut h = H::new();
    let c = h.cash(&alice(), 2, 1);
    let at = h.now - 1;
    let (note, sig) = (input(&c[0]), signed(&c[0], enter_digest_spec(&c[0], 0, &POSITION, at)));
    let e = h.refused(&agent(), move |p| p.enter(0, note, sig, outs(&POSITION), at));
    assert!(e.contains("expired"), "{e}");
    let shares = h.enter(&c[0], 0, &POSITION);
    let n = &shares[9];
    let (note, sig) = (input(n), signed(n, leave_digest_spec(n, &ONE_TO_CASH, at)));
    let e = h.refused(&agent(), move |p| p.leave(0, note, sig, outs(&ONE_TO_CASH), at));
    assert!(e.contains("expired"), "{e}");
    let cash = h.cash(&alice(), 1, 1);
    let (note, sig) = (input(&cash[0]), signed(&cash[0], exit_digest(&cash[0], &alice(), 0, at)));
    let e = h.refused(&agent(), move |p| p.pay_exit(note, sig, alice(), at));
    assert!(e.contains("expired"), "{e}");
}

#[test]
fn an_entry_at_a_stale_price_is_refused() {
    // An entry at a price that ignores unread rewards would take them from the holders.
    let mut h = H::new();
    h.position(0, &alice());
    h.place(0, IN_POSITION);
    h.now += SYNC_FRESH_NS + 1;
    let c = h.cash(&acc("x.test"), 2, 1);
    let e = h.refused_enter(&c[0], 0, &POSITION);
    assert!(e.contains("sync this vault first"), "{e}");
    h.sync_by(&mallory(), 0, IN_POSITION + NEAR);
    assert!(h.vault(0).share_price.0 > INITIAL_PRICE);
    let e = h.refused(&mallory(), |p| p.sync(0));
    assert!(e.contains("read less than an hour ago"), "{e}");
}

#[test]
fn a_leave_is_paid_at_once_from_the_vaults_liquid_funds() {
    let mut h = H::new();
    let shares = h.position(0, &alice());
    let cash_before = h.cash_view().liquid.0;
    let n = &shares[9];
    let cash = h.leave(n, &ONE_TO_CASH);
    let v = h.vault(0);
    assert_eq!(v.total_shares.0, 9_900_000 - SHARES[1]);
    assert_eq!(v.liquid.0, IN_POSITION - NEAR);
    assert_eq!(h.cash_view().liquid.0, cash_before + NEAR - NOTE_STORAGE_FEE);
    assert_eq!(h.cash_view().outstanding.0, 9 * CASH[0]);
    assert!(h.cash_view().liquid.0 >= h.cash_view().outstanding.0, "the cash is always fully backed");
    h.logs.clear();
    pay(&mut h, &cash[0], &alice());
    assert!(h.logs.iter().all(|l| !l.contains("vault")), "{:?}", h.logs);
}

#[test]
fn a_holder_cannot_dodge_a_loss_by_leaving_before_it_is_read() {
    // With the money staked, a leave paid from fresh cash would pass a later loss on to those who stay.
    let mut h = H::new();
    let alices = h.position(0, &alice());
    h.position(0, &bob());
    h.place(0, 2 * IN_POSITION);
    h.cash(&acc("carol.test"), 2, 3); // fresh cash in the compartment
    let e = h.refused_leave(&alices[9], &ONE_TO_CASH);
    assert!(e.contains("not enough liquid funds in this vault"), "{e}");
    // The loss is read before any money comes back: alice leaves at the new price like everyone.
    h.sync(0, IN_POSITION);
    h.withdraw(0, IN_POSITION);
    let price = h.vault(0).share_price.0;
    assert_eq!(price, INITIAL_PRICE / 2);
    h.leave(&alices[9], &[(0, 4)]);
}

#[test]
fn leaving_moves_no_yield_to_those_who_stay() {
    // A leave used to leave its money staked against a fixed debt, so the shares left behind took its yield.
    let mut h = H::with(None, 100_000 * NEAR, 100_000 * NEAR);
    let small = h.cash(&mallory(), 1, 1);
    let m = h.enter(&small[0], 0, &[(0, 9)]);
    let mut big = h.position(0, &alice());
    big.extend(h.position(0, &alice()));
    for n in big.iter().filter(|n| n.token.denom_id == 1) {
        h.leave(n, &ONE_TO_CASH);
    }
    assert_eq!(h.vault(0).share_price.0, INITIAL_PRICE, "a leave does not move the price");
    let left = h.vault(0).liquid.0;
    h.place(0, left);
    h.sync(0, left + left / 100);
    let price = h.vault(0).share_price.0;
    assert!(price <= INITIAL_PRICE / 100 * 101, "those who stay gain 1 %, not more: {price}");
    let mallory_value = m.len() as u128 * SHARES[0] * price;
    assert!(mallory_value <= 9 * CASH[0] / 100 * 101 + 9);
}

#[test]
fn a_loss_of_half_halves_the_price_and_every_holder_is_paid() {
    let mut h = H::new();
    let a = h.position(0, &alice());
    let b = h.position(0, &bob());
    h.place(0, 2 * IN_POSITION);
    h.sync(0, IN_POSITION);
    h.withdraw(0, IN_POSITION);
    assert_eq!(h.vault(0).share_price.0, INITIAL_PRICE / 2);
    for n in a.iter().chain(b.iter()).filter(|n| n.token.denom_id == 1) {
        h.leave(n, &[(0, 4)]);
    }
    let v = h.vault(0);
    assert_eq!(v.share_price.0, INITIAL_PRICE / 2, "the first to leave were not paid more");
    assert_eq!(v.liquid.0, v.total_shares.0 * v.share_price.0, "what is left pays exactly the notes left");
}

#[test]
fn gains_on_few_shares_go_to_their_holders() {
    let mut h = H::new();
    let c = h.cash(&alice(), 1, 1);
    h.enter(&c[0], 0, &[(0, 9)]);
    h.place(0, 9 * CASH[0]);
    h.sync(0, 9 * CASH[0] + 5 * NEAR);
    assert_eq!(h.vault(0).share_price.0, (9 * CASH[0] + 5 * NEAR) / (9 * SHARES[0]));
}

#[test]
fn what_is_left_in_an_emptied_vault_belongs_to_nobody() {
    let mut h = H::new();
    let c = h.cash(&alice(), 1, 1);
    let notes = h.enter(&c[0], 0, &[(0, 9)]);
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    for n in &notes {
        escape(&mut h, &mallory(), n, &alice());
    }
    assert_eq!(h.vault(0).total_shares.0, 0);
    h.sync_by(&mallory(), 0, NEAR / 2); // rewards found at the target afterwards
    h.sync(1, 0);
    h.now += HOUR_NS;
    h.sync(0, NEAR / 2);
    let c = h.cash(&bob(), 2, 1);
    h.enter(&c[0], 0, &POSITION);
    let v = h.vault(0);
    assert_eq!(v.share_price.0, INITIAL_PRICE, "the newcomer does not take what was left");
}

// ---- notes and owners ----

#[test]
fn a_note_named_in_an_exit_request_can_only_exit() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 2, 1);
    request(&mut h, &notes[0], &alice());
    cancel(&mut h, &notes[0], &alice());
    let e = h.refused_enter(&notes[0], 0, &POSITION);
    assert!(e.contains("a note named in an exit request can only exit"), "{e}");
    let shares = h.position(0, &alice());
    request(&mut h, &shares[9], &alice());
    cancel(&mut h, &shares[9], &alice());
    let e = h.refused_leave(&shares[9], &ONE_TO_CASH);
    assert!(e.contains("a note named in an exit request can only exit"), "{e}");
    pay(&mut h, &notes[0], &alice());
}

#[test]
fn an_owner_key_serves_one_note_only() {
    let mut h = H::new();
    h.cash(&alice(), 1, 2);
    let owner = SigningKey::generate(&mut OsRng);
    let first = h.cash_note_owned_by(1, &owner);
    let second = h.cash_note_owned_by(1, &owner);
    pay(&mut h, &first, &alice());
    let e = refused_pay(&mut h, &second, &alice());
    assert!(e.contains("this owner key already served another note"), "{e}");
}

#[test]
fn the_agent_waits_for_enough_live_notes_in_a_tier() {
    let mut h = H::build(None, 1_000 * NEAR, 1_000 * NEAR, 1_000 * NEAR, 3);
    let a = h.cash(&alice(), 1, 2);
    let e = refused_pay(&mut h, &a[0], &alice());
    assert!(e.contains("too few live notes in this tier"), "{e}");
    let tens = h.cash(&alice(), 2, 1);
    let e = h.refused_enter(&tens[0], 0, &POSITION);
    assert!(e.contains("too few live notes in this tier"), "{e}");
    h.cash(&bob(), 1, 1);
    pay(&mut h, &a[0], &alice());
    let e = refused_pay(&mut h, &a[1], &alice());
    assert!(e.contains("too few live notes in this tier"), "two left: {e}");
    // Without the agent, the escape pays anyway.
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    escape(&mut h, &mallory(), &a[1], &alice());
}

#[test]
fn a_cash_exit_pays_the_signed_depositor_and_names_no_vault() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 1);
    h.transfers.clear();
    h.logs.clear();
    pay(&mut h, &notes[0], &alice());
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE)]);
    assert!(h.logs.iter().all(|l| !l.contains("vault")), "{:?}", h.logs);
}

#[test]
fn no_one_can_be_paid_without_a_valid_note() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 2);
    let n = &notes[0];
    h.position(0, &alice());
    let mut forged = h.share_note(0, 1);
    forged.vault = None;
    let e = refused_pay(&mut h, &forged, &alice());
    assert!(e.contains("invalid note"), "{e}");
    let (note, sig) = (input(n), signed(n, exit_digest(n, &alice(), 0, FAR)));
    let e = h.refused(&agent(), move |p| p.pay_exit(note, sig, bob(), FAR));
    assert!(e.contains("bad owner signature"), "{e}");
    let (note, sig) = (input(n), signed(n, exit_digest(n, &alice(), 0, FAR)));
    let e = h.refused(&mallory(), move |p| p.pay_exit(note, sig, alice(), FAR));
    assert!(e.contains("only the agent"), "{e}");
    pay(&mut h, n, &alice());
    let e = refused_pay(&mut h, n, &alice());
    assert!(e.contains("note already spent"), "{e}");
    assert!(h.view(|p| p.is_spent(b64(&nf(&notes[0])))));
}

#[test]
fn exits_go_only_to_an_account_that_deposited() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 1);
    let e = refused_pay(&mut h, &notes[0], &mallory());
    assert!(e.contains("only to an account that deposited"), "{e}");
}

#[test]
fn exits_never_exceed_the_notes_issued() {
    let mut h = H::new();
    let issued = h.cash(&alice(), 1, 1);
    h.cash(&bob(), 2, 1);
    let extra = h.cash_note(1);
    pay(&mut h, &issued[0], &alice());
    let e = refused_pay(&mut h, &extra, &alice());
    assert!(e.contains("more exits than notes issued"), "{e}");
}

#[test]
fn a_note_key_of_small_order_is_refused() {
    // The neutral point as owner key, with R = neutral and S = 0, signs anything.
    let mut h = H::new();
    h.cash(&alice(), 1, 1);
    let mut pk = [0u8; 32];
    pk[0] = 1;
    let nonce = [7u8; 32];
    let mut msg = vec![1u8];
    msg.extend_from_slice(&pk);
    msg.extend_from_slice(&nonce);
    let dst = cash_dst(NETWORK, contract().as_str()).into_bytes();
    let (r, b) = blind(&msg, &dst, &mut OsRng);
    let sig = unblind(&sign_blinded(&h.cash_keys[1], &b).unwrap(), &r).unwrap();
    let mut owner_sig = [0u8; 64];
    owner_sig[0] = 1;
    let note = NoteInput { tier: 1, pk: b64(&pk), nonce: b64(&nonce), sig: b64(&sig) };
    let e = h.refused(&agent(), move |p| p.pay_exit(note, b64(&owner_sig), alice(), FAR));
    assert!(e.contains("bad owner signature"), "{e}");
}

#[test]
fn the_refused_keys_are_exactly_points_of_small_order() {
    let mut checked = 0;
    for k in WEAK_KEYS {
        if let Ok(key) = VerifyingKey::from_bytes(&k) {
            assert!(key.is_weak(), "{k:?}");
            checked += 1;
        }
    }
    assert!(checked >= 8, "every small-order point is in the list: {checked}");
}

// ---- requests and the escape ----

#[test]
fn only_the_paid_account_files_its_exit_request() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 1);
    let n = &notes[0];
    let (note, sig) = (input(n), signed(n, exit_digest(n, &alice(), 0, FAR)));
    let e = h.refused_paying(&mallory(), REQUEST_FEE, move |p| p.request_exit(None, note, sig, alice(), U128(0), FAR));
    assert!(e.contains("filed by the account it pays"), "{e}");
    let (note, sig) = (input(n), signed(n, exit_digest(n, &alice(), 0, FAR)));
    let e = h.refused(&alice(), move |p| p.request_exit(None, note, sig, alice(), U128(0), FAR));
    assert!(e.contains("attach the storage fee"), "{e}");
}

#[test]
fn a_request_fee_goes_back_to_whoever_paid_it() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 2);
    let mark = h.mark();
    request(&mut h, &notes[0], &alice());
    assert_eq!(h.status().held_fees.0, REQUEST_FEE);
    h.transfers.clear();
    pay(&mut h, &notes[0], &alice());
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE), (alice(), REQUEST_FEE - mark)]);
    request(&mut h, &notes[1], &alice());
    h.transfers.clear();
    cancel(&mut h, &notes[1], &alice());
    assert_eq!(h.transfers, vec![(alice(), REQUEST_FEE - mark)]);
    assert_eq!(h.status().held_fees.0, 0);
}

#[test]
fn a_request_made_again_waits_again_and_three_withdrawals_end_it() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 1);
    request(&mut h, &notes[0], &alice());
    cancel(&mut h, &notes[0], &alice());
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, 0);
    }
    request(&mut h, &notes[0], &alice());
    assert!(!h.cash_view().open, "a new request waits the whole delay");
    let e = refused_escape(&mut h, &mallory(), &notes[0], &alice());
    assert!(e.contains("the agent is still active"), "{e}");
    cancel(&mut h, &notes[0], &alice());
    request(&mut h, &notes[0], &alice());
    cancel(&mut h, &notes[0], &alice());
    let n = &notes[0];
    let until = h.now + DAY_NS;
    let (note, sig) = (input(n), signed(n, exit_digest(n, &alice(), 0, until)));
    let e = h.refused_paying(&alice(), REQUEST_FEE, move |p| p.request_exit(None, note, sig, alice(), U128(0), until));
    assert!(e.contains("withdrawn too many times"), "{e}");
}

#[test]
fn a_request_that_can_no_longer_be_paid_is_removed_by_anyone() {
    let mut h = H::new();
    let c = acc("c.test");
    let notes = h.cash(&c, 1, 2);
    let soon = h.now + DAY_NS;
    request_until(&mut h, &notes[0], &c, soon);
    request(&mut h, &notes[1], &c);
    // The limit is checked over all the account's waiting requests.
    let x = acc("x.test");
    let own = h.cash(&x, 1, 1);
    let other = h.cash(&bob(), 1, 1);
    request(&mut h, &own[0], &x);
    let until = h.now + DAY_NS;
    let (note, sig, to) = (input(&other[0]), signed(&other[0], exit_digest(&other[0], &x, 0, until)), x.clone());
    let e = h.refused_paying(&x, REQUEST_FEE, move |p| p.request_exit(None, note, sig, to, U128(0), until));
    assert!(e.contains("waiting exits exceed its exit limit"), "{e}");
    let id = b64(&nf(&notes[0]));
    let early = id.clone();
    let e = h.refused(&mallory(), move |p| p.drop_request(None, early));
    assert!(e.contains("can still be paid"), "{e}");
    h.now += DAY_NS + 1;
    let mark = h.mark();
    h.transfers.clear();
    h.call(&mallory(), move |p| p.drop_request(None, id));
    assert_eq!(h.transfers, vec![(c.clone(), REQUEST_FEE - mark)], "the fee goes back to whoever paid it");
    assert_eq!(h.cash_view().requests, 2);
}

#[test]
fn the_escape_opens_only_after_seven_days_without_the_agent() {
    let mut h = H::new();
    let cash = h.cash(&alice(), 1, 2);
    let shares = h.position(0, &alice());
    h.place(0, IN_POSITION);
    h.now += DEFAULT_ESCAPE_DELAY_NS - 1;
    let e = refused_escape(&mut h, &mallory(), &cash[0], &alice());
    assert!(e.contains("the agent is still active"), "{e}");
    let e = h.refused(&mallory(), |p| p.unstake(0, None));
    assert!(e.contains("only the agent while it is active"), "{e}");

    h.now += 1;
    assert!(h.view(|p| p.escape_open()));
    h.transfers.clear();
    escape(&mut h, &mallory(), &cash[0], &alice());
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE)]);
    // With the agent gone no cash can be signed, so share notes leave their vault directly.
    h.unstake_by(&mallory(), 0, Some(1));
    assert_eq!(h.last_amount("unstake"), format!("{{\"amount\":\"{IN_POSITION}\"}}"), "everything, not what the caller chose");
    h.withdraw_by(&mallory(), 0, None);
    h.sync_by(&mallory(), 0, 0);
    h.transfers.clear();
    h.logs.clear();
    escape(&mut h, &mallory(), &shares[9], &alice());
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE)]);
    assert!(h.logs.iter().any(|l| l.contains("\"event\":\"share_exit\"")));
}

#[test]
fn others_withdraw_at_most_once_an_hour() {
    let mut h = H::new();
    h.position(0, &alice());
    h.place(0, IN_POSITION);
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    h.withdraw_by(&mallory(), 0, None);
    h.sync_by(&mallory(), 0, NEAR); // rewards still at the target
    let e = h.refused(&bob(), |p| p.withdraw(0, None));
    assert!(e.contains("withdrawn by someone else less than an hour ago"), "{e}");
    h.now += HOUR_NS;
    h.withdraw_by(&bob(), 0, None);
}

#[test]
fn normal_and_escape_exits_share_one_hourly_window() {
    let mut h = H::build(None, 1_000 * NEAR, 1_000 * NEAR, 20 * NEAR, 1);
    let notes = h.cash(&alice(), 2, 3);
    pay(&mut h, &notes[0], &alice());
    pay(&mut h, &notes[1], &alice());
    h.call(&guardian(), |p| p.set_agent(acc("agent2.test")));
    request(&mut h, &notes[2], &alice());
    let e = refused_escape(&mut h, &mallory(), &notes[2], &alice());
    assert!(e.contains("hourly limit reached"), "the escape does not double the rate: {e}");
    h.now += HOUR_NS;
    escape(&mut h, &mallory(), &notes[2], &alice());
}

#[test]
fn only_placements_syncs_and_paid_exits_count_as_agent_activity() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 2);
    h.position(0, &bob());
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    assert!(h.view(|p| p.escape_open()));
    h.cash(&bob(), 1, 1);
    h.call(&agent(), |p| p.claim_fees(0));
    assert!(h.view(|p| p.escape_open()), "issues and fees do not restart the delay");
    pay(&mut h, &notes[0], &alice());
    assert!(!h.view(|p| p.escape_open()), "a paid exit does");
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    h.call(&agent(), |p| p.sync(0));
    assert!(!h.view(|p| p.escape_open()), "so does a sync");
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    h.sync_by(&agent(), 0, 0);
    h.place(0, NEAR);
    assert!(!h.view(|p| p.escape_open()), "and a placement");
}

#[test]
fn an_active_agent_that_does_not_pay_cannot_keep_a_cash_holder_waiting() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 1);
    request(&mut h, &notes[0], &alice());
    for _ in 0..6 {
        h.now += DAY_NS;
        h.sync(0, 0);
    }
    h.now += DAY_NS - 1;
    let e = refused_escape(&mut h, &mallory(), &notes[0], &alice());
    assert!(e.contains("the agent is still active"), "{e}");
    h.now += 1;
    assert!(!h.view(|p| p.escape_open()));
    assert!(h.cash_view().open);
    let mark = h.mark();
    h.transfers.clear();
    escape(&mut h, &mallory(), &notes[0], &alice());
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE), (alice(), REQUEST_FEE - mark)]);
    assert!(!h.cash_view().open, "once paid, the request opens nothing");
}

#[test]
fn a_share_holder_the_agent_ignores_can_open_its_vault() {
    let mut h = H::new();
    let shares = h.position(0, &alice());
    h.place(0, IN_POSITION);
    let n = &shares[9];
    request(&mut h, n, &alice());
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, IN_POSITION);
    }
    assert!(h.vault(0).open);
    let e = h.refused(&agent(), |p| p.place(0, U128(1)));
    assert!(e.contains("open to holders"), "{e}");
    h.unstake_by(&mallory(), 0, None);
    assert_eq!(h.last_amount("unstake"), format!("{{\"amount\":\"{NEAR}\"}}"), "only what the request needs");
    h.withdraw_by(&mallory(), 0, None);
    h.transfers.clear();
    escape(&mut h, &mallory(), n, &alice());
    assert_eq!(h.transfers[0], (alice(), NEAR - EXIT_STORAGE_FEE));
}

#[test]
fn funds_brought_back_for_a_waiting_request_are_kept_for_it() {
    // The agent used to let a partner's note leave with the funds a third party had just brought back.
    let mut h = H::new();
    let a = h.position(0, &alice());
    let m = h.position(0, &mallory());
    let total = 2 * IN_POSITION;
    h.place(0, total);
    request(&mut h, &a[9], &alice());
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, total);
    }
    assert!(h.vault(0).open);
    h.unstake_by(&bob(), 0, None);
    h.now += 2 * DAY_NS;
    h.sync(0, total);
    h.withdraw_by(&bob(), 0, None);
    assert_eq!(h.vault(0).liquid.0, NEAR);
    let e = h.refused_leave(&m[9], &ONE_TO_CASH);
    assert!(e.contains("kept for the exit requests waiting on this vault"), "{e}");
    h.transfers.clear();
    escape(&mut h, &bob(), &a[9], &alice());
    assert_eq!(h.transfers[0], (alice(), NEAR - EXIT_STORAGE_FEE));
}

#[test]
fn while_the_agent_is_active_the_escape_serves_only_holders_who_asked() {
    let mut h = H::new();
    let a = h.position(0, &alice());
    let m = h.position(0, &mallory());
    let total = 2 * IN_POSITION;
    h.place(0, total);
    request(&mut h, &a[9], &alice());
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, total);
    }
    h.unstake_by(&bob(), 0, None);
    h.now += 2 * DAY_NS;
    h.sync(0, total);
    h.withdraw_by(&bob(), 0, None);
    let e = refused_escape(&mut h, &bob(), &m[9], &mallory());
    assert!(e.contains("only notes with an exit request leave by the escape"), "{e}");
    escape(&mut h, &bob(), &a[9], &alice());
}

#[test]
fn the_agents_own_unstake_does_not_hold_back_the_one_the_contract_fixes() {
    let mut h = H::new();
    let a = h.position(0, &alice());
    h.place(0, IN_POSITION);
    request(&mut h, &a[9], &alice());
    for _ in 0..6 {
        h.now += DAY_NS;
        h.sync(0, IN_POSITION);
    }
    h.now += DAY_NS - 2 * HOUR_NS;
    h.unstake_by(&agent(), 0, Some(1)); // just before the request is overdue
    h.now += 2 * HOUR_NS;
    h.sync(0, IN_POSITION);
    assert!(h.vault(0).open);
    h.unstake_by(&bob(), 0, None);
    assert_eq!(h.last_amount("unstake"), format!("{{\"amount\":\"{NEAR}\"}}"));
}

#[test]
fn the_last_notes_of_a_tier_leave_by_request_and_escape_with_an_active_agent() {
    // Below the minimum of live notes the agent cannot pay; the owner asks, waits the delay and leaves.
    let mut h = H::build(None, 1_000 * NEAR, 1_000 * NEAR, 1_000 * NEAR, 3);
    let a = h.cash(&alice(), 1, 2);
    let e = refused_pay(&mut h, &a[0], &alice());
    assert!(e.contains("too few live notes in this tier"), "{e}");
    request(&mut h, &a[0], &alice());
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, 0);
    }
    assert!(!h.view(|p| p.escape_open()), "the agent is active");
    assert!(h.cash_view().open);
    let e = refused_escape(&mut h, &mallory(), &a[1], &alice());
    assert!(e.contains("only notes with an exit request"), "the open cash list does not pay every note: {e}");
    escape(&mut h, &mallory(), &a[0], &alice());
}

#[test]
fn a_request_list_kept_full_by_partners_does_not_trap_a_holder() {
    // 16 partner accounts fill the cash list with requests the active agent never pays.
    let mut h = H::new();
    for i in 0..16 {
        let c = acc(&format!("c{i}.test"));
        for n in h.cash(&c, 0, 4) {
            request(&mut h, &n, &c);
        }
    }
    assert_eq!(h.cash_view().requests, MAX_REQUESTS as u32);
    let mine = h.cash(&alice(), 1, 1);
    let until = h.now + DAY_NS;
    let (note, sig) = (input(&mine[0]), signed(&mine[0], exit_digest(&mine[0], &alice(), 0, until)));
    let e = h.refused_paying(&alice(), REQUEST_FEE, move |p| p.request_exit(None, note, sig, alice(), U128(0), until));
    assert!(e.contains("too many exit requests waiting"), "{e}");
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, 0);
    }
    assert!(!h.view(|p| p.escape_open()), "the agent is active");
    h.transfers.clear();
    escape(&mut h, &mallory(), &mine[0], &alice());
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE)], "a list full for the delay lets anyone out");
}

#[test]
fn a_vault_list_kept_full_by_partners_does_not_trap_a_share_holder() {
    // 16 partners fill a vault's list while the active agent keeps everything staked: the forced unstake must
    // bring back more than the partners' requests, or Alice's unlisted note can never leave.
    let mut h = H::new();
    let a = h.position(0, &alice());
    let mut total = IN_POSITION;
    let mut partners = Vec::new();
    for i in 0..16 {
        let c = acc(&format!("c{i}.test"));
        let n = h.position(0, &c);
        total += IN_POSITION;
        partners.push((c, n));
    }
    h.place(0, total);
    for (c, n) in &partners {
        for k in 0..4 {
            request(&mut h, &n[k], c);
        }
    }
    assert_eq!(h.vault(0).requests, MAX_REQUESTS as u32);
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, total);
    }
    assert!(!h.view(|p| p.escape_open()), "agent active");
    assert!(h.vault(0).open);
    h.unstake_by(&bob(), 0, None);
    assert_eq!(h.last_amount("unstake"), format!("{{\"amount\":\"{total}\"}}"), "everything comes back");
    h.now += 2 * DAY_NS;
    h.sync(0, total);
    h.withdraw_by(&bob(), 0, None);
    h.transfers.clear();
    escape(&mut h, &bob(), &a[0], &alice());
    assert_eq!(h.transfers, vec![(alice(), CASH[0] - EXIT_STORAGE_FEE)]);
}

#[test]
fn a_list_no_longer_full_stops_opening_the_escape_to_everyone() {
    let mut h = H::new();
    let mut listed = Vec::new();
    for i in 0..16 {
        let c = acc(&format!("c{i}.test"));
        for n in h.cash(&c, 0, 4) {
            request(&mut h, &n, &c);
            listed.push((c.clone(), n));
        }
    }
    for (c, n) in listed.iter().take(31) {
        cancel(&mut h, n, c);
    }
    assert_eq!(h.cash_view().requests, 33);
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, 0);
    }
    let mine = h.cash(&alice(), 1, 1);
    let e = refused_escape(&mut h, &mallory(), &mine[0], &alice());
    assert!(e.contains("only notes with an exit request"), "{e}");
    // The holders who asked still leave.
    let (c, n) = &listed[40];
    escape(&mut h, &mallory(), n, c);
}

#[test]
fn a_request_whose_owner_key_served_another_note_can_be_removed() {
    let mut h = H::new();
    h.cash(&alice(), 1, 2);
    let owner = SigningKey::generate(&mut OsRng);
    let first = h.cash_note_owned_by(1, &owner);
    let second = h.cash_note_owned_by(1, &owner);
    request(&mut h, &first, &alice());
    pay(&mut h, &second, &alice());
    let id = b64(&nf(&first));
    h.call(&mallory(), move |p| p.drop_request(None, id));
    assert_eq!(h.cash_view().requests, 0);
    // And a request cannot wait forever.
    let n = h.cash_note(1);
    let far = h.now + MAX_REQUEST_LIFE_NS + 1;
    let (note, sig) = (input(&n), signed(&n, exit_digest(&n, &alice(), 0, far)));
    let e = h.refused_paying(&alice(), REQUEST_FEE, move |p| p.request_exit(None, note, sig, alice(), U128(0), far));
    assert!(e.contains("a request lasts at most 30 days"), "{e}");
}

#[test]
fn the_agent_fee_never_takes_funds_kept_for_a_request() {
    let mut h = H::new();
    let a = h.position(0, &alice());
    h.place(0, IN_POSITION);
    h.call(&guardian(), |p| p.set_fee_bps(2_000));
    h.now += ADMIN_NS;
    h.sync(0, IN_POSITION);
    h.sync(0, IN_POSITION + NEAR);
    assert!(h.vault(0).fee_owed.0 > 0);
    request(&mut h, &a[9], &alice());
    h.withdraw(0, NEAR);
    let before = h.vault(0).fee_owed.0;
    h.transfers.clear();
    h.call(&agent(), |p| p.claim_fees(0));
    assert!(h.transfers.is_empty(), "the 1 NEAR back is kept for alice's request");
    assert_eq!(h.vault(0).fee_owed.0, before);
}

#[test]
fn the_agent_pays_a_listed_request() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 1);
    request(&mut h, &notes[0], &alice());
    let id = b64(&nf(&notes[0]));
    let other = id.clone();
    let e = h.refused(&mallory(), move |p| p.pay_request(None, other));
    assert!(e.contains("only the agent"), "{e}");
    h.transfers.clear();
    h.call(&agent(), move |p| p.pay_request(None, id));
    assert_eq!(h.transfers[0], (alice(), NEAR - EXIT_STORAGE_FEE));
    // A listed share note is paid under its own event name.
    let shares = h.position(0, &bob());
    request(&mut h, &shares[9], &bob());
    let id = b64(&nf(&shares[9]));
    h.logs.clear();
    h.call(&agent(), move |p| p.pay_request(Some(0), id));
    assert!(h.logs.iter().any(|l| l.contains("\"event\":\"share_exit\"")), "{:?}", h.logs);
    assert!(h.logs.iter().all(|l| !l.contains("escape")), "{:?}", h.logs);
}

#[test]
fn a_strict_staking_pool_still_returns_everything_after_the_agent_unstaked_one_yocto() {
    // The staking pool refuses to unstake more than is staked or withdraw more than is unstaked. An agent that
    // unstakes 1 yocto before going silent must not make the forced unstake and withdraw fail.
    let mut h = H::new();
    h.strict = true;
    let a = h.position(0, &alice());
    h.place(0, IN_POSITION);
    assert!(h.unstake_by(&agent(), 0, Some(1)));
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    assert!(!h.unstake_by(&mallory(), 0, None), "nothing is unstaked while unstaked funds wait");
    assert!(h.withdraw_by(&mallory(), 0, None), "the waiting yocto comes back first");
    assert_eq!(h.last_amount("withdraw"), "{\"amount\":\"1\"}");
    assert!(h.unstake_by(&mallory(), 0, None), "asks for what is staked, not for `placed`");
    assert_eq!(h.last_amount("unstake"), format!("{{\"amount\":\"{}\"}}", IN_POSITION - 1));
    h.now += 2 * DAY_NS;
    assert!(h.withdraw_by(&mallory(), 0, None), "asks for what is unstaked");
    assert_eq!(h.last_amount("withdraw"), format!("{{\"amount\":\"{}\"}}", IN_POSITION - 1));
    h.sync_by(&mallory(), 0, 0);
    h.transfers.clear();
    escape(&mut h, &mallory(), &a[9], &alice());
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE)]);
}

#[test]
fn a_strict_staking_pool_returns_everything_when_a_vault_list_stays_full() {
    let mut h = H::new();
    h.strict = true;
    let a = h.position(0, &alice());
    let mut total = IN_POSITION;
    let mut partners = Vec::new();
    for i in 0..16 {
        let c = acc(&format!("c{i}.test"));
        let n = h.position(0, &c);
        total += IN_POSITION;
        partners.push((c, n));
    }
    h.place(0, total);
    assert!(h.unstake_by(&agent(), 0, Some(1)));
    for (c, n) in &partners {
        for k in 0..4 {
            request(&mut h, &n[k], c);
        }
    }
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, total);
    }
    assert!(!h.unstake_by(&bob(), 0, None), "the agent's yocto must come back first");
    assert!(h.withdraw_by(&bob(), 0, None));
    assert!(h.unstake_by(&bob(), 0, None));
    h.now += 2 * DAY_NS;
    h.sync(0, total - 1);
    assert!(h.withdraw_by(&bob(), 0, None));
    h.transfers.clear();
    escape(&mut h, &bob(), &a[0], &alice());
    assert_eq!(h.transfers, vec![(alice(), CASH[0] - EXIT_STORAGE_FEE)]);
}

#[test]
fn a_saboteur_cannot_keep_unstaked_funds_locked_by_unstaking_again() {
    // Each unstake may push back the release of everything already unstaked: a new forced unstake waits for the
    // withdrawal, so repeating it every three days cannot keep the funds locked.
    let mut h = H::new();
    h.strict = true;
    let a = h.position(0, &alice());
    h.place(0, IN_POSITION);
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    assert!(h.unstake_by(&mallory(), 0, None));
    h.now += UNSTAKE_INTERVAL_NS;
    h.sync_by(&mallory(), 0, IN_POSITION);
    let unlock = h.unlock_at[0];
    assert!(!h.unstake_by(&mallory(), 0, None), "the saboteur's second unstake is not sent");
    assert_eq!(h.unlock_at[0], unlock, "the lock was not pushed back");
    assert!(h.withdraw_by(&bob(), 0, None));
    h.transfers.clear();
    escape(&mut h, &bob(), &a[9], &alice());
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE)]);
}

#[test]
fn a_failed_unstake_does_not_start_the_interval_and_others_cannot_choose_the_amount() {
    // A failed call, or one of 1 yocto, by anyone used to block unstaking for three days.
    let mut h = H::new();
    h.position(0, &alice());
    h.place(0, IN_POSITION);
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    h.call(&mallory(), |p| p.unstake(0, Some(U128(1))));
    assert_eq!(h.self_call("on_staked_read")["amount"], json!(IN_POSITION.to_string()), "not what the caller chose");
    // The staking pool does not answer: the vault is freed and no interval starts.
    let op = h.vault(0).busy_op;
    h.callback_with(vec![PromiseResult::Failed, PromiseResult::Failed], |p| p.on_staked_read(0, op, U128(IN_POSITION)));
    assert!(!h.vault(0).busy);
    assert!(h.unstake_by(&alice(), 0, None));
    assert_eq!(h.last_amount("unstake"), format!("{{\"amount\":\"{IN_POSITION}\"}}"));
    let e = h.refused(&mallory(), |p| p.unstake(0, None));
    assert!(e.contains("unstaked too recently"), "{e}");
    h.now += UNSTAKE_INTERVAL_NS;
    h.unstake_by(&mallory(), 0, None);
}

#[test]
fn no_placement_while_an_announcement_is_pending_and_others_bring_back_only_what_is_needed() {
    // After an announcement, anyone used to unstake everything while the agent staked it again.
    let mut h = H::new();
    h.position(0, &alice());
    h.place(0, 5 * NEAR);
    h.call(&guardian(), |p| p.set_agent(acc("agent2.test")));
    assert!(h.view(|p| p.escape_open()));
    let e = h.refused(&mallory(), |p| p.unstake(0, None));
    assert!(e.contains("nothing to bring back"), "no request waits, so nothing is unstaked: {e}");
    let e = h.refused(&agent(), |p| p.place(0, U128(NEAR)));
    assert!(e.contains("announcement is pending") || e.contains("open to holders"), "{e}");
    h.now += ADMIN_NS;
    h.sync_by(&acc("agent2.test"), 0, 5 * NEAR);
    h.call(&acc("agent2.test"), |p| p.place(0, U128(NEAR)));
}

#[test]
fn a_new_fee_waits_and_never_charges_gains_read_before_it() {
    let mut h = H::new();
    h.position(0, &alice());
    h.place(0, IN_POSITION);
    let e = h.refused(&guardian(), |p| p.set_fee_bps(MAX_FEE_BPS + 1));
    assert!(e.contains("fee too high"), "{e}");
    let e = h.refused(&alice(), |p| p.set_fee_bps(1_000));
    assert!(e.contains("only the guardian"), "{e}");
    h.call(&guardian(), |p| p.set_fee_bps(2_000));
    assert_eq!(h.view(|p| p.get_config().fee_bps), 0);
    assert_eq!(h.view(|p| p.get_config().pending_fee_bps), Some(2_000));
    h.now += ADMIN_NS; // 1 NEAR of rewards earned meanwhile, read only now
    h.sync(0, IN_POSITION + NEAR);
    assert_eq!(h.vault(0).fee_owed.0, 0, "gains read by a sync started before the change keep the old rate");
    let before = h.vault(0).share_price.0;
    h.sync(0, IN_POSITION + 2 * NEAR);
    let gain = (IN_POSITION + 2 * NEAR) / 9_900_000 - before;
    let fee = h.vault(0).fee_owed.0;
    assert!(fee > 0 && fee <= gain * 9_900_000 / 5, "20 % at most of the new gain");
}

#[test]
fn the_agent_fee_is_zero_by_default() {
    let mut h = H::new();
    h.position(0, &alice());
    h.place(0, IN_POSITION);
    h.sync(0, IN_POSITION + NEAR);
    assert_eq!(h.vault(0).fee_owed.0, 0);
}

#[test]
fn leaves_count_in_the_vaults_hourly_window_and_one_large_note_still_passes() {
    let mut h = H::with(None, 1_000 * NEAR, 2 * NEAR);
    let shares = h.position(0, &alice());
    let ones: Vec<&Note> = shares.iter().filter(|n| n.token.denom_id == 1).collect();
    h.leave(ones[0], &ONE_TO_CASH);
    h.leave(ones[1], &ONE_TO_CASH);
    let e = h.refused_leave(ones[2], &ONE_TO_CASH);
    assert!(e.contains("hourly limit reached"), "{e}");
    // In a new hour, one note worth more than the cap still leaves.
    h.place(0, 7 * NEAR);
    h.now += HOUR_NS;
    h.sync(0, 7 * NEAR * 3);
    h.withdraw(0, 7 * NEAR * 3);
    let price = h.vault(0).share_price.0;
    assert!(SHARES[1] * price > 2 * NEAR);
    let value = SHARES[1] * price - NOTE_STORAGE_FEE;
    let count = (value / CASH[1]) as u64;
    let small = ((value - u128::from(count) * CASH[1]) / CASH[0]) as u64;
    h.leave(ones[2], &[(1, count), (0, small)]);
}

#[test]
fn a_late_sync_answer_does_not_overwrite_the_balance() {
    let mut h = H::new();
    h.position(0, &alice());
    h.call(&agent(), |p| p.sync(0));
    let stale = h.vault(0).busy_op;
    h.now += BUSY_TIMEOUT_NS;
    h.place(0, IN_POSITION);
    h.callback(PromiseResult::Successful(b"\"0\"".to_vec()), |p| p.on_sync(0, stale));
    assert_eq!(h.vault(0).placed.0, IN_POSITION);
}

#[test]
fn a_late_callback_does_not_free_the_operation_that_replaced_it() {
    let mut h = H::new();
    h.position(0, &alice());
    h.call(&agent(), |p| p.place(0, U128(NEAR)));
    let first = h.vault(0).busy_op;
    h.now += BUSY_TIMEOUT_NS;
    h.call(&agent(), |p| p.sync(0));
    h.callback(PromiseResult::Successful(vec![]), |p| p.on_place(0, U128(NEAR), first));
    assert!(h.vault(0).busy);
}

#[test]
fn a_returned_payout_is_kept_for_its_holder() {
    let mut h = H::new();
    let notes = h.cash(&alice(), 1, 1);
    pay(&mut h, &notes[0], &alice());
    let amount = NEAR - EXIT_STORAGE_FEE;
    h.balance += amount;
    h.callback(PromiseResult::Failed, |p| p.on_payout(alice(), U128(amount)));
    assert_eq!(h.holder(&alice()).owed.0, amount);
    h.transfers.clear();
    h.call(&alice(), |p| p.claim_owed());
    assert_eq!(h.transfers, vec![(alice(), amount)]);
}

#[test]
fn a_new_agent_waits_for_the_admin_delay() {
    let mut h = H::new();
    h.call(&guardian(), |p| p.set_agent(acc("agent2.test")));
    assert_eq!(h.view(|p| p.get_config().pending_agent), Some(acc("agent2.test")));
    let e = h.refused(&acc("agent2.test"), |p| p.issue_cash(alice(), 0, 1));
    assert!(e.contains("only the agent"), "{e}");
    h.now += ADMIN_NS;
    assert_eq!(h.view(|p| p.get_config().agent), acc("agent2.test"));
    let e = h.refused(&agent(), |p| p.issue_cash(alice(), 0, 1));
    assert!(e.contains("only the agent"), "{e}");
}

#[test]
fn a_new_vault_waits_for_the_admin_delay() {
    let mut h = H::new();
    let id = h.add_vault(1_000 * NEAR, 1_000 * NEAR);
    let c = h.cash(&bob(), 2, 1);
    let e = h.refused_enter(&c[0], id, &POSITION);
    assert!(e.contains("announcement is pending") || e.contains("not active yet"), "{e}");
    h.now += ADMIN_NS;
    h.enter(&c[0], id, &POSITION);
}

#[test]
fn deposit_cash_entry_gains_leave_and_exit_never_show_an_account_with_a_vault() {
    let mut h = H::new();
    h.logs.clear();
    h.public.clear();
    let cash = h.cash(&alice(), 2, 1);
    let shares = h.enter(&cash[0], 0, &POSITION);
    h.place(0, IN_POSITION);
    h.now += DAY_NS;
    h.sync(0, IN_POSITION + IN_POSITION / 50); // 2 % of gains
    h.withdraw(0, IN_POSITION + IN_POSITION / 50);
    let price = h.vault(0).share_price.0;
    let value = SHARES[1] * price - NOTE_STORAGE_FEE;
    let count = (value / CASH[1]) as u64;
    let small = ((value - u128::from(count) * CASH[1]) / CASH[0]) as u64;
    let list: Vec<(u8, u64)> = [(1u8, count), (0u8, small)].into_iter().filter(|(_, c)| *c > 0).collect();
    let back = h.leave(&shares[9], &list);
    h.transfers.clear();
    for n in &back {
        pay(&mut h, n, &alice());
    }
    let received: u128 = h.transfers.iter().map(|(_, a)| a).sum();
    assert_eq!(received, back.iter().map(|n| CASH[usize::from(n.token.denom_id)] - EXIT_STORAGE_FEE).sum::<u128>());
    // The arguments of every public call: an account and a vault never travel together.
    for (method, args) in &h.public {
        let text = args.to_string();
        let names_account = text.contains("alice");
        let names_vault = args.get("vault_id").is_some();
        assert!(!(names_account && names_vault), "{method}: {text}");
        if method == "pay_exit" {
            assert!(!names_vault, "{text}");
        }
        if method == "enter" || method == "leave" {
            assert!(!names_account, "{text}");
        }
    }
    assert!(h.public.iter().any(|(m, _)| m == "pay_exit"));
    for log in &h.logs {
        let names_account = log.contains("alice");
        let names_vault = log.contains("\"vault\"");
        assert!(!(names_account && names_vault), "{log}");
        if log.contains("\"event\":\"exit\"") {
            assert!(!names_vault, "{log}");
        }
    }
    for event in ["enter", "leave", "exit"] {
        assert!(h.logs.iter().any(|l| l.contains(&format!("\"event\":\"{event}\""))), "{event}");
    }
}
