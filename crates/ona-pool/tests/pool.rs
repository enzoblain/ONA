//! The pool on the mocked NEAR VM, which runs the real BLS12-381 and ed25519 host functions. Share notes are
//! made with `ona-token` (blst), and the exit digest is recomputed here with `sha2`, so both sides are
//! cross-checked. Vault calls are only inspected as receipts: no staking pool runs here.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ed25519_dalek::SigningKey;
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::mock::MockAction;
use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
use near_sdk::{env, testing_env, AccountId, Gas, NearToken, PromiseResult};
use ona_pool::*;
use ona_token::{keygen, sign_blinded, sign_digest, PendingToken, SecretKey, Token, G2_LEN};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const NETWORK: &str = "sandbox";
/// One note of tier 0 holds 10^6 shares, one NEAR at the initial price; tier 1 holds ten times more.
const TIER_SHARES: [u128; 2] = [1_000_000, 10_000_000];
/// The guardian's announcement delay used by these tests.
const ADMIN_SECS: u64 = 7 * 86_400;
const ADMIN_NS: u64 = ADMIN_SECS * 1_000_000_000;

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

/// Written from the SPEC, independently of the contract.
fn nullifier(vault: u32, t: &Token) -> [u8; 32] {
    sha(&[b"ONA-POOL-NF-V1", &vault.to_le_bytes(), &[t.denom_id], &t.pk, &t.nonce])
}

fn digest(vault: u32, nf: &[u8; 32], to: &AccountId, min: u128) -> [u8; 32] {
    sha(&[
        b"ONA-POOL-EXIT-V1",
        &sha(&[contract().as_bytes()]),
        &vault.to_le_bytes(),
        nf,
        &sha(&[to.as_bytes()]),
        &min.to_le_bytes(),
    ])
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

#[derive(Debug, Clone)]
struct Call {
    to: AccountId,
    method: String,
    args: String,
    deposit: u128,
}

struct Note {
    token: Token,
    owner: SigningKey,
    vault: u32,
}

struct H {
    pool: Pool,
    balance: u128,
    storage: u64,
    now: u64,
    keys: Vec<Vec<SecretKey>>,
    pks: Vec<Vec<[u8; G2_LEN]>>,
    transfers: Vec<(AccountId, u128)>,
    calls: Vec<Call>,
}

impl H {
    fn with(escape_secs: Option<u64>, max_assets: u128, hourly: u128) -> Self {
        let now = 1_000 * HOUR_NS;
        let balance = 5 * NEAR;
        context(&acc("deployer.test"), balance, 0, now);
        let pool = Pool::new(guardian(), agent(), NETWORK.into(), escape_secs, Some(ADMIN_SECS));
        let mut h = Self {
            pool,
            balance,
            storage: env::storage_usage(),
            now,
            keys: Vec::new(),
            pks: Vec::new(),
            transfers: Vec::new(),
            calls: Vec::new(),
        };
        h.add_vault(max_assets, hourly);
        h.add_vault(max_assets, hourly);
        // The listed vaults take effect, then the agent shows it is active.
        h.now += ADMIN_NS;
        h.sync(0, 0);
        h.calls.clear();
        h
    }

    fn new() -> Self {
        Self::with(None, 1_000 * NEAR, 1_000 * NEAR)
    }

    fn add_vault(&mut self, max_assets: u128, hourly: u128) -> u32 {
        let keys: Vec<SecretKey> = (0..2).map(|_| keygen(&mut OsRng)).collect();
        let pks: Vec<[u8; G2_LEN]> = keys.iter().map(|k| k.public_key()).collect();
        let tiers = pks
            .iter()
            .zip(TIER_SHARES)
            .map(|(pk, shares)| TierInit { shares: U128(shares), pk_g2: b64(pk) })
            .collect();
        let id = self.pks.len() as u32;
        let got = self.call(&guardian(), |p| {
            p.add_vault("staking".into(), staking(id), b64(&[7; 32]), tiers, U128(max_assets), U128(hourly))
        });
        assert_eq!(got, id);
        self.keys.push(keys);
        self.pks.push(pks);
        id
    }

    /// Runs one method, applies its outgoing transfers and deposits, and checks that the pool still covers
    /// storage, the vaults' liquid funds and what it owes.
    fn call<R>(&mut self, pred: &AccountId, f: impl FnOnce(&mut Pool) -> R) -> R {
        self.call_paying(pred, 0, f)
    }

    fn call_paying<R>(&mut self, pred: &AccountId, attached: u128, f: impl FnOnce(&mut Pool) -> R) -> R {
        self.balance += attached;
        context_paying(pred, attached, self.balance, self.storage, self.now);
        let r = f(&mut self.pool);
        self.storage = env::storage_usage();
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
            vec![result]
        );
        f(&mut self.pool);
        self.storage = env::storage_usage();
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

    /// A plain transfer to the pool, with no method call, such as an `ona-mint` spend.
    fn plain_transfer(&mut self, amount: u128) {
        self.balance += amount;
    }

    /// The depositor pays the pool through `deposit`.
    fn deposit(&mut self, who: &AccountId, credited: u128) {
        self.call_paying(who, credited + DEPOSIT_STORAGE_FEE, |p| p.deposit());
    }

    /// Money in, shares recorded, notes signed blind by the agent.
    fn enter(&mut self, vault: u32, tier: u8, count: u64, depositor: &AccountId) -> Vec<Note> {
        let price = self.vault(vault).share_price.0;
        let cost = TIER_SHARES[usize::from(tier)] * price * u128::from(count);
        self.deposit(depositor, cost);
        let U128(got) = self.call(&agent(), |p| p.record_entry(vault, tier, count));
        assert_eq!(got, cost);
        (0..count).map(|_| self.note(vault, tier)).collect()
    }

    fn note(&self, vault: u32, tier: u8) -> Note {
        let dst = note_dst(NETWORK, contract().as_str(), vault).into_bytes();
        let pending = PendingToken::new(&mut OsRng, tier, &dst).unwrap();
        let sig = sign_blinded(&self.keys[vault as usize][usize::from(tier)], &pending.blinded).unwrap();
        let (token, owner) = pending.finish(&sig, &self.pks[vault as usize][usize::from(tier)]).unwrap();
        Note { token, owner, vault }
    }

    /// Delivers the callback of the operation the vault is busy with.
    fn reply(&mut self, vault: u32, result: PromiseResult, f: impl FnOnce(&mut Pool, u64)) {
        let op = self.vault(vault).busy_op;
        self.callback(result, |p| f(p, op));
    }

    fn place(&mut self, vault: u32, amount: u128) {
        self.call(&agent(), |p| p.place(vault, U128(amount)));
        self.reply(vault, PromiseResult::Successful(vec![]), |p, op| p.on_place(vault, U128(amount), op));
    }

    /// The target reports what it holds for the pool.
    fn sync(&mut self, vault: u32, total: u128) {
        self.call(&agent(), |p| p.sync(vault));
        let reply = format!("\"{total}\"").into_bytes();
        self.reply(vault, PromiseResult::Successful(reply), |p, op| p.on_sync(vault, op));
    }

    /// Funds come back from the target to the pool.
    fn withdraw(&mut self, vault: u32, amount: u128) {
        self.call(&agent(), |p| p.withdraw(vault, U128(amount)));
        self.balance += amount;
        self.reply(vault, PromiseResult::Successful(vec![]), |p, op| p.on_withdraw(vault, U128(amount), op));
    }

    fn holder(&mut self, a: &AccountId) -> HolderView {
        self.view(|p| p.get_holder(a.clone()))
    }
}

fn input(n: &Note) -> NoteInput {
    NoteInput { tier: n.token.denom_id, pk: b64(&n.token.pk), nonce: b64(&n.token.nonce), sig: b64(&n.token.sig) }
}

/// The owner's signature on an exit of `n` from `vault` to `to`.
fn signed(n: &Note, vault: u32, to: &AccountId, min: u128) -> Base64VecU8 {
    b64(&sign_digest(&n.owner, &digest(vault, &nullifier(vault, &n.token), to, min)))
}

fn pay(h: &mut H, n: &Note, to: &AccountId) {
    let sig = signed(n, n.vault, to, 0);
    let (vault, note, to) = (n.vault, input(n), to.clone());
    h.call(&agent(), move |p| p.pay_exit(vault, note, sig, to, U128(0)));
}

fn refused_exit(h: &mut H, pred: &AccountId, n: &Note, vault: u32, sig: Base64VecU8, to: &AccountId) -> String {
    let (note, to) = (input(n), to.clone());
    h.refused(pred, move |p| p.pay_exit(vault, note, sig, to, U128(0)))
}

// ---- liste blanche ----

#[test]
fn only_the_guardian_lists_vaults_and_lending_is_not_built() {
    let mut h = H::new();
    let pk = keygen(&mut OsRng).public_key();
    let tiers = vec![TierInit { shares: U128(1), pk_g2: b64(&pk) }];
    let t = tiers.clone();
    let e = h.refused(&agent(), move |p| {
        p.add_vault("staking".into(), staking(9), b64(&[7; 32]), t, U128(NEAR), U128(NEAR));
    });
    assert!(e.contains("only the guardian"), "{e}");
    let t = tiers.clone();
    let e = h.refused(&guardian(), move |p| {
        p.add_vault("lending".into(), staking(9), b64(&[7; 32]), t, U128(NEAR), U128(NEAR));
    });
    assert!(e.contains("lending adapter not implemented"), "{e}");
    let t = tiers.clone();
    let e = h.refused(&guardian(), move |p| {
        p.add_vault("swap".into(), staking(9), b64(&[7; 32]), t, U128(NEAR), U128(NEAR));
    });
    assert!(e.contains("unknown adapter"), "{e}");
    let t = tiers;
    let e = h.refused(&guardian(), move |p| {
        p.add_vault("staking".into(), staking(9), b64(&[7; 31]), t, U128(NEAR), U128(NEAR));
    });
    assert!(e.contains("bad code hash length"), "{e}");
}

#[test]
fn the_checked_code_hash_is_published_with_the_vault() {
    let mut h = H::new();
    assert_eq!(h.vault(0).code_hash.0, vec![7; 32]);
}

#[test]
fn a_key_cannot_serve_two_vaults() {
    let mut h = H::new();
    let reused = h.pks[0][0];
    let e = h.refused(&guardian(), move |p| {
        let tiers = vec![TierInit { shares: U128(1), pk_g2: b64(&reused) }];
        p.add_vault("staking".into(), staking(9), b64(&[7; 32]), tiers, U128(NEAR), U128(NEAR));
    });
    assert!(e.contains("key already used"), "{e}");
}

#[test]
fn the_agent_calls_only_listed_vaults_and_only_their_methods() {
    let mut h = H::new();
    h.enter(0, 1, 1, &alice());
    let e = h.refused(&agent(), |p| p.place(7, U128(NEAR)));
    assert!(e.contains("unknown vault"), "{e}");
    let e = h.refused(&alice(), |p| p.place(0, U128(NEAR)));
    assert!(e.contains("only the agent"), "{e}");

    h.place(0, 4 * NEAR);
    h.call(&agent(), |p| p.unstake(0, U128(NEAR)));
    h.reply(0, PromiseResult::Successful(vec![]), |p, op| p.on_done(0, op));
    h.withdraw(0, NEAR);
    h.sync(0, 3 * NEAR);

    let external: Vec<&Call> = h.calls.iter().filter(|c| c.to != contract()).collect();
    assert_eq!(external.len(), 4);
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
    h.enter(0, 1, 1, &alice());
    h.call(&agent(), |p| p.place(0, U128(NEAR)));
    let e = h.refused(&agent(), |p| p.sync(0));
    assert!(e.contains("still running"), "{e}");
    h.now += BUSY_TIMEOUT_NS;
    h.call(&agent(), |p| p.sync(0));
}

#[test]
fn a_failed_placement_returns_to_the_vaults_liquid_funds() {
    let mut h = H::new();
    h.enter(0, 1, 1, &alice());
    h.call(&agent(), |p| p.place(0, U128(4 * NEAR)));
    h.balance += 4 * NEAR; // a failed call sends its deposit back
    h.reply(0, PromiseResult::Failed, |p, op| p.on_place(0, U128(4 * NEAR), op));
    let v = h.vault(0);
    assert_eq!((v.liquid.0, v.placed.0, v.busy), (10 * NEAR, 0, false));
}

// ---- aucun transfert libre ----

#[test]
fn an_exit_pays_only_the_signed_depositor_and_nothing_else() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 1, &alice());
    h.transfers.clear();
    pay(&mut h, &notes[0], &alice());
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE)]);
    assert_eq!(h.vault(0).liquid.0, 0);
}

#[test]
fn no_one_can_be_paid_without_a_valid_note() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 2, &alice());
    let n = &notes[0];

    // Signed by a key that is not the vault's.
    let mut forged = h.note(1, 0);
    forged.vault = 0;
    let sig = signed(&forged, 0, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), &forged, 0, sig, &alice());
    assert!(e.contains("invalid note"), "{e}");

    // A note of vault 0 presented to vault 1, with a fresh owner signature for vault 1.
    let sig = signed(n, 1, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), n, 1, sig, &alice());
    assert!(e.contains("invalid note"), "{e}");

    // The agent changes the recipient the owner signed.
    let sig = signed(n, 0, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), n, 0, sig, &bob());
    assert!(e.contains("bad owner signature"), "{e}");

    // Nobody but the agent, while it is active.
    let sig = signed(n, 0, &alice(), 0);
    let e = refused_exit(&mut h, &mallory(), n, 0, sig, &alice());
    assert!(e.contains("only the agent"), "{e}");

    // A minimum above what the note is worth.
    let sig = signed(n, 0, &alice(), NEAR);
    let (note, s) = (input(n), sig);
    let e = h.refused(&agent(), move |p| p.pay_exit(0, note, s, alice(), U128(NEAR)));
    assert!(e.contains("below the owner's minimum"), "{e}");
}

#[test]
fn exits_go_only_to_an_account_that_deposited() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 1, &alice());
    let sig = signed(&notes[0], 0, &mallory(), 0);
    let e = refused_exit(&mut h, &agent(), &notes[0], 0, sig, &mallory());
    assert!(e.contains("only to an account that deposited"), "{e}");
}

#[test]
fn only_money_paid_through_deposit_can_be_given_to_a_vault() {
    let mut h = H::new();
    // The pool's own funding and a plain transfer are not deposits.
    h.plain_transfer(20 * NEAR);
    let e = h.refused(&agent(), |p| {
        p.record_entry(0, 1, 1);
    });
    assert!(e.contains("not enough unassigned funds"), "{e}");
    let e = h.refused(&alice(), |p| p.deposit());
    assert!(e.contains("deposit too small"), "{e}");
}

#[test]
fn nobody_can_declare_a_depositor_for_someone_else() {
    // There is no method that names a depositor: `deposit` credits its own caller only.
    let mut h = H::new();
    h.deposit(&agent(), 10 * NEAR);
    h.deposit(&guardian(), 10 * NEAR);
    assert_eq!(h.holder(&alice()).deposited.0, 0);
    assert_eq!(h.holder(&agent()).deposited.0, 10 * NEAR);
    assert_eq!(h.status().unassigned.0, 20 * NEAR);
    // So notes paid for by the agent cannot be sent to an account that never deposited.
    h.call(&agent(), |p| p.record_entry(0, 1, 1));
    let note = h.note(0, 1);
    let sig = signed(&note, 0, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), &note, 0, sig, &alice());
    assert!(e.contains("only to an account that deposited"), "{e}");
}

#[test]
fn a_withdrawal_in_flight_cannot_be_given_to_a_vault() {
    let mut h = H::new();
    h.enter(0, 1, 1, &alice());
    h.place(0, 10 * NEAR);
    h.call(&agent(), |p| p.withdraw(0, U128(10 * NEAR)));
    assert_eq!(h.vault(0).withdrawing.0, 10 * NEAR);
    h.balance += 10 * NEAR; // the transfer lands before the callback
    let e = h.refused(&agent(), |p| {
        p.record_entry(1, 1, 1);
    });
    assert!(e.contains("not enough unassigned funds"), "{e}");
    h.reply(0, PromiseResult::Successful(vec![]), |p, op| p.on_withdraw(0, U128(10 * NEAR), op));
    let v = h.vault(0);
    assert_eq!((v.withdrawing.0, v.liquid.0, v.placed.0), (0, 10 * NEAR, 0));
}

// ---- double dépense ----

#[test]
fn a_note_is_paid_once() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 2, &alice());
    pay(&mut h, &notes[0], &alice());
    let sig = signed(&notes[0], 0, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), &notes[0], 0, sig, &alice());
    assert!(e.contains("note already spent"), "{e}");
    let nf = nullifier(0, &notes[0].token);
    assert!(h.view(|p| p.is_spent(b64(&nf))));
    pay(&mut h, &notes[1], &alice());
}

#[test]
fn exits_never_exceed_the_notes_recorded() {
    let mut h = H::new();
    h.enter(0, 0, 1, &alice());
    h.enter(0, 1, 1, &alice());
    // A note the agent signed without recording it.
    let extra = h.note(0, 0);
    let first = h.note(0, 0);
    pay(&mut h, &first, &alice());
    let sig = signed(&extra, 0, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), &extra, 0, sig, &alice());
    assert!(e.contains("more exits than notes issued"), "{e}");
}

// ---- prix de part et commission ----

#[test]
fn the_share_price_follows_what_the_vault_holds() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 2, &alice());
    assert_eq!(h.vault(0).share_price.0, INITIAL_PRICE);
    h.place(0, 2 * NEAR);
    h.sync(0, 2 * NEAR + NEAR / 5);
    let price = h.vault(0).share_price.0;
    assert_eq!(price, INITIAL_PRICE / 10 * 11, "2.2 NEAR for 2 million shares");

    // A later entry pays the new price, so it does not take the earlier gains.
    let later = h.enter(0, 0, 1, &bob());
    assert_eq!(h.holder(&bob()).deposited.0, NEAR / 10 * 11);

    h.withdraw(0, 2 * NEAR + NEAR / 5);
    h.transfers.clear();
    pay(&mut h, &notes[0], &alice());
    pay(&mut h, &later[0], &bob());
    let worth = NEAR / 10 * 11 - EXIT_STORAGE_FEE;
    assert_eq!(h.transfers, vec![(alice(), worth), (bob(), worth)]);
}

#[test]
fn the_agent_fee_is_zero_by_default() {
    let mut h = H::new();
    assert_eq!(h.view(|p| p.get_config().fee_bps), 0);
    h.enter(0, 0, 2, &alice());
    h.place(0, 2 * NEAR);
    h.sync(0, 3 * NEAR);
    assert_eq!(h.vault(0).fee_owed.0, 0);
}

#[test]
fn a_fee_is_charged_only_on_gains_above_the_highest_price() {
    let mut h = H::new();
    h.enter(0, 0, 2, &alice());
    h.place(0, 2 * NEAR);
    h.sync(0, 2 * NEAR + NEAR / 5);
    let e = h.refused(&alice(), |p| p.set_fee_bps(1_000));
    assert!(e.contains("only the guardian"), "{e}");
    let e = h.refused(&guardian(), |p| p.set_fee_bps(MAX_FEE_BPS + 1));
    assert!(e.contains("fee too high"), "{e}");
    h.call(&guardian(), |p| p.set_fee_bps(1_000));
    assert_eq!(h.vault(0).fee_owed.0, 0, "gains made before the fee was set are not charged");

    h.sync(0, 2 * NEAR + 2 * NEAR / 5);
    assert_eq!(h.vault(0).fee_owed.0, NEAR / 50, "10 % of a 0.2 NEAR gain");

    h.sync(0, 2 * NEAR);
    h.sync(0, 2 * NEAR + 2 * NEAR / 5 - NEAR / 50);
    assert_eq!(h.vault(0).fee_owed.0, NEAR / 50, "climbing back after a loss is not charged again");

    h.withdraw(0, NEAR);
    h.transfers.clear();
    h.call(&agent(), |p| p.claim_fees(0));
    assert_eq!(h.transfers, vec![(agent(), NEAR / 50)]);
    assert_eq!(h.vault(0).fee_owed.0, 0);
}

// ---- séquestre et sortie de secours ----

#[test]
fn the_escape_opens_only_after_seven_days_without_the_agent() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 2, &alice());
    h.place(0, NEAR);

    h.now += DEFAULT_ESCAPE_DELAY_NS - 1;
    let sig = signed(&notes[0], 0, &alice(), 0);
    let note = input(&notes[0]);
    let e = h.refused(&mallory(), move |p| p.escape_exit(0, note, sig, alice(), U128(0)));
    assert!(e.contains("the agent is still active"), "{e}");
    let e = h.refused(&mallory(), |p| p.withdraw(0, U128(NEAR)));
    assert!(e.contains("only the agent while it is active"), "{e}");

    h.now += 1;
    assert!(h.view(|p| p.escape_open()));
    // Anyone can bring the placed funds back, then pay a holder what the note is worth.
    h.call(&mallory(), |p| p.unstake(0, U128(NEAR)));
    h.reply(0, PromiseResult::Successful(vec![]), |p, op| p.on_done(0, op));
    h.call(&mallory(), |p| p.withdraw(0, U128(NEAR)));
    h.balance += NEAR;
    h.reply(0, PromiseResult::Successful(vec![]), |p, op| p.on_withdraw(0, U128(NEAR), op));
    h.transfers.clear();
    for n in &notes {
        let sig = signed(n, 0, &alice(), 0);
        let note = input(n);
        h.call(&mallory(), move |p| p.escape_exit(0, note, sig, alice(), U128(0)));
    }
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE); 2]);
}

#[test]
fn only_placements_syncs_and_paid_exits_count_as_agent_activity() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 2, &alice());
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    assert!(h.view(|p| p.escape_open()));

    // Work that moves nothing for holders does not close the escape.
    h.deposit(&bob(), NEAR);
    h.call(&agent(), |p| p.record_entry(1, 0, 1));
    h.call(&agent(), |p| p.claim_fees(0));
    h.call(&guardian(), |p| p.set_agent(acc("agent2.test")));
    h.call(&guardian(), |p| p.set_agent(agent()));
    h.now += ADMIN_NS;
    assert!(h.view(|p| p.escape_open()), "entries, fees and a new agent do not restart the delay");

    pay(&mut h, &notes[0], &alice());
    assert!(!h.view(|p| p.escape_open()), "a paid exit does");
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    h.call(&agent(), |p| p.sync(0));
    assert!(!h.view(|p| p.escape_open()), "so does a sync");
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    h.place(0, NEAR / 2);
    assert!(!h.view(|p| p.escape_open()), "and a placement");
    let _ = notes;
}

#[test]
fn an_active_agent_that_does_not_pay_cannot_keep_a_holder_waiting() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 1, &alice());
    h.place(0, NEAR); // everything is placed
    let n = &notes[0];
    let note = input(n);
    let sig = signed(n, 0, &alice(), 0);
    // A request pays its storage and needs a valid note signed for an account that deposited.
    let (nt, s) = (note.clone(), sig.clone());
    let e = h.refused(&mallory(), move |p| p.request_exit(0, nt, s, alice(), U128(0)));
    assert!(e.contains("attach 0.001 NEAR"), "{e}");
    let (nt, s) = (note.clone(), signed(n, 0, &mallory(), 0));
    let e = h.refused_paying(&mallory(), REQUEST_STORAGE_FEE, move |p| p.request_exit(0, nt, s, mallory(), U128(0)));
    assert!(e.contains("only to an account that deposited"), "{e}");
    let (nt, s) = (note.clone(), sig.clone());
    h.call_paying(&mallory(), REQUEST_STORAGE_FEE, move |p| p.request_exit(0, nt, s, alice(), U128(0)));

    // The agent keeps syncing every day, so the general escape stays closed.
    for _ in 0..6 {
        h.now += DAY_NS;
        h.sync(0, NEAR);
    }
    h.now += DAY_NS - 1;
    let (nt, s) = (note.clone(), sig.clone());
    let e = h.refused(&mallory(), move |p| p.escape_exit(0, nt, s, alice(), U128(0)));
    assert!(e.contains("the agent is still active"), "{e}");
    let e = h.refused(&mallory(), |p| p.withdraw(0, U128(NEAR)));
    assert!(e.contains("only the agent while it is active"), "{e}");

    h.now += 1;
    assert!(!h.view(|p| p.escape_open()));
    // The overdue request stops placements in this vault and lets anyone bring its funds back.
    h.deposit(&bob(), NEAR);
    h.call(&agent(), |p| p.record_entry(0, 0, 1));
    let e = h.refused(&agent(), |p| p.place(0, U128(NEAR)));
    assert!(e.contains("overdue"), "{e}");
    let e = h.refused(&agent(), |p| p.unstake(0, U128(NEAR)));
    assert!(e.contains("the escape is open on this vault"), "the agent cannot restart the lock");
    h.call(&mallory(), |p| p.unstake(0, U128(NEAR)));
    h.reply(0, PromiseResult::Successful(vec![]), |p, op| p.on_done(0, op));
    h.call(&mallory(), |p| p.withdraw(0, U128(NEAR)));
    h.balance += NEAR;
    h.reply(0, PromiseResult::Successful(vec![]), |p, op| p.on_withdraw(0, U128(NEAR), op));
    h.transfers.clear();
    h.call(&mallory(), move |p| p.escape_exit(0, note, sig, alice(), U128(0)));
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE)]);
    // Once paid, the request no longer blocks the vault.
    h.place(0, NEAR);
}

#[test]
fn a_depositor_takes_back_money_never_placed_once_the_escape_opens() {
    let mut h = H::new();
    h.deposit(&alice(), 5 * NEAR);
    h.enter(0, 0, 2, &alice()); // 2 NEAR given to a vault, 5 still unassigned
    let e = h.refused(&alice(), |p| p.refund_deposit(U128(NEAR)));
    assert!(e.contains("the agent is still active"), "{e}");
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    let e = h.refused(&mallory(), |p| p.refund_deposit(U128(NEAR)));
    assert!(e.contains("not a depositor"), "{e}");
    let e = h.refused(&alice(), |p| p.refund_deposit(U128(5 * NEAR + 1)));
    assert!(e.contains("more than this account's share"), "{e}");
    h.transfers.clear();
    h.call(&alice(), |p| p.refund_deposit(U128(5 * NEAR)));
    assert_eq!(h.transfers, vec![(alice(), 5 * NEAR)]);
    assert_eq!(h.status().unassigned.0, 0);
    let me = h.holder(&alice());
    assert_eq!((me.refunded.0, me.withdrawn.0), (5 * NEAR, 0));
    assert_eq!(me.exit_limit.0, 2 * NEAR, "what is left to exit is what went to the vault");
}

#[test]
fn a_refund_never_exceeds_the_accounts_share() {
    let mut h = H::new();
    h.deposit(&alice(), NEAR);
    h.deposit(&bob(), 5 * NEAR);
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    let e = h.refused(&alice(), |p| p.refund_deposit(U128(2 * NEAR)));
    assert!(e.contains("more than this account's share"), "{e}");
    h.call(&alice(), |p| p.refund_deposit(U128(NEAR)));
    let e = h.refused(&alice(), |p| p.refund_deposit(U128(1)));
    assert!(e.contains("more than this account's share"), "{e}");
    assert_eq!(h.holder(&bob()).refundable.0, 5 * NEAR);
}

#[test]
fn an_account_whose_money_was_placed_cannot_take_anothers_unassigned_money_and_exit_too() {
    let mut h = H::new();
    let x = acc("x.test");
    let y = acc("y.test");
    let notes = h.enter(0, 1, 1, &x); // X's 10 NEAR went to vault 0
    h.deposit(&y, 10 * NEAR); // Y's 10 NEAR were never placed
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    // X gets only its share of what is unassigned, not all of Y's money.
    assert_eq!(h.holder(&x).refundable.0, 5 * NEAR);
    let e = h.refused(&x, |p| p.refund_deposit(U128(10 * NEAR)));
    assert!(e.contains("more than this account's share"), "{e}");
    h.call(&x, |p| p.refund_deposit(U128(5 * NEAR)));
    // And what X took back comes off what it can still exit.
    assert_eq!(h.holder(&x).exit_limit.0, 5 * NEAR);
    let (note, sig) = (input(&notes[0]), signed(&notes[0], 0, &x, 0));
    let e = h.refused(&mallory(), move |p| p.escape_exit(0, note, sig, x.clone(), U128(0)));
    assert!(e.contains("over this account's exit limit"), "{e}");
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
    h.transfers.clear();
    h.call(&alice(), |p| p.refund_deposit(U128(3 * NEAR)));
    assert_eq!(h.transfers, vec![(alice(), 3 * NEAR)]);
}

#[test]
fn a_new_agent_waits_for_the_admin_delay_and_the_escape_is_open_meanwhile() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 2, &alice());
    h.place(0, NEAR / 2);
    assert!(!h.view(|p| p.escape_open()));
    h.call(&guardian(), |p| p.set_agent(acc("agent2.test")));
    assert!(h.view(|p| p.escape_open()), "holders can leave before the change");
    assert_eq!(h.view(|p| p.get_config().pending_agent), Some(acc("agent2.test")));
    // The old agent still runs things, the new one cannot yet.
    let e = h.refused(&acc("agent2.test"), |p| p.place(0, U128(NEAR / 4)));
    assert!(e.contains("only the agent"), "{e}");
    let (note, sig) = (input(&notes[0]), signed(&notes[0], 0, &alice(), 0));
    h.call(&mallory(), move |p| p.escape_exit(0, note, sig, alice(), U128(0)));

    h.now += ADMIN_NS;
    assert_eq!(h.view(|p| p.get_config().agent), acc("agent2.test"));
    let e = h.refused(&agent(), |p| p.place(0, U128(NEAR / 4)));
    assert!(e.contains("only the agent"), "{e}");
    h.call(&acc("agent2.test"), |p| p.sync(0));
    assert!(!h.view(|p| p.escape_open()), "the new agent's work closes it");
}

#[test]
fn a_new_vault_waits_for_the_admin_delay_and_the_escape_is_open_meanwhile() {
    let mut h = H::new();
    h.enter(0, 0, 1, &alice());
    h.place(0, NEAR / 2);
    let id = h.add_vault(1_000 * NEAR, 1_000 * NEAR);
    assert!(h.view(|p| p.escape_open()));
    h.deposit(&bob(), NEAR);
    let e = h.refused(&agent(), move |p| {
        p.record_entry(id, 0, 1);
    });
    assert!(e.contains("vault not active yet"), "{e}");
    h.now += ADMIN_NS;
    h.sync(0, NEAR / 2);
    assert!(!h.view(|p| p.escape_open()));
    h.call(&agent(), move |p| p.record_entry(id, 0, 1));
}

#[test]
fn the_admin_delay_is_at_least_seven_days() {
    let _h = H::new();
    context(&acc("deployer.test"), NEAR, 0, 0);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(|| Pool::new(guardian(), agent(), NETWORK.into(), None, Some(7 * 86_400 - 1)));
    std::panic::set_hook(hook);
    assert!(panic_text(r.err().unwrap()).contains("admin delay must be between 7 and 30 days"));
}

#[test]
fn an_exit_that_could_not_be_paid_cannot_be_requested() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 6, &alice());
    let n = &notes[0];
    // A minimum above what the note is worth.
    let (note, sig) = (input(n), signed(n, 0, &alice(), NEAR));
    let e = h.refused_paying(&alice(), REQUEST_STORAGE_FEE, move |p| p.request_exit(0, note, sig, alice(), U128(NEAR)));
    assert!(e.contains("this exit could not be paid"), "{e}");
    // At most four waiting requests per account and vault.
    for n in &notes[..4] {
        let (note, sig) = (input(n), signed(n, 0, &alice(), 0));
        h.call_paying(&alice(), REQUEST_STORAGE_FEE, move |p| p.request_exit(0, note, sig, alice(), U128(0)));
    }
    let (note, sig) = (input(&notes[4]), signed(&notes[4], 0, &alice(), 0));
    let e = h.refused_paying(&alice(), REQUEST_STORAGE_FEE, move |p| p.request_exit(0, note, sig, alice(), U128(0)));
    assert!(e.contains("too many exit requests for this account"), "{e}");
    // The account can withdraw a request, nobody else can.
    let nf = b64(&nullifier(0, &notes[0].token));
    let other = nf.clone();
    let e = h.refused(&mallory(), move |p| p.cancel_exit_request(0, other));
    assert!(e.contains("no such request"), "{e}");
    h.call(&alice(), move |p| p.cancel_exit_request(0, nf));
    assert_eq!(h.vault(0).requests, 3);
}

#[test]
fn a_request_that_can_no_longer_be_paid_does_not_block_the_vault() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 1, &alice());
    h.place(0, NEAR);
    let (note, sig) = (input(&notes[0]), signed(&notes[0], 0, &alice(), 0));
    h.call_paying(&alice(), REQUEST_STORAGE_FEE, move |p| p.request_exit(0, note, sig, alice(), U128(0)));
    // The vault loses everything: the note is now worthless.
    h.sync(0, 0);
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, 0);
    }
    assert!(!h.view(|p| p.escape_open()));
    h.deposit(&bob(), NEAR);
    let e = h.refused(&mallory(), |p| p.withdraw(0, U128(1)));
    assert!(e.contains("only the agent while it is active"), "an unpayable request opens nothing");
    // Placing in it is still allowed (entries are not: its price is below the floor).
    let e = h.refused(&agent(), |p| p.place(0, U128(1)));
    assert!(e.contains("amount above the vault's liquid funds"), "{e}");
}

fn request(h: &mut H, n: &Note, to: &AccountId) {
    let (note, sig, to) = (input(n), signed(n, n.vault, to, 0), to.clone());
    let vault = n.vault;
    h.call_paying(&to.clone(), REQUEST_STORAGE_FEE, move |p| p.request_exit(vault, note, sig, to, U128(0)));
}

#[test]
fn an_agent_recycling_a_full_request_list_does_not_keep_an_honest_holder_out() {
    let mut h = H::new();
    let crowd: Vec<AccountId> = (0..16).map(|i| acc(&format!("c{i}.test"))).collect();
    let mut first = Vec::new();
    for c in &crowd {
        let notes = h.enter(0, 0, 4, c);
        for n in &notes {
            request(&mut h, n, c);
        }
        first.push(notes);
    }
    assert_eq!(h.vault(0).requests, MAX_REQUESTS as u32);
    let honest = h.enter(0, 0, 1, &alice());
    let (note, sig) = (input(&honest[0]), signed(&honest[0], 0, &alice(), 0));
    let e = h.refused_paying(&alice(), REQUEST_STORAGE_FEE, move |p| p.request_exit(0, note, sig, alice(), U128(0)));
    assert!(e.contains("too many exit requests waiting"), "{e}");

    // Every day one request is withdrawn and made again, and the agent keeps syncing.
    for day in 0..7 {
        h.now += DAY_NS;
        let (c, n) = (&crowd[day], &first[day][0]);
        let nf = b64(&nullifier(0, &n.token));
        h.call(c, move |p| p.cancel_exit_request(0, nf));
        request(&mut h, n, c);
        h.sync(0, 0);
    }
    assert!(!h.view(|p| p.escape_open()));
    h.transfers.clear();
    let (note, sig) = (input(&honest[0]), signed(&honest[0], 0, &alice(), 0));
    h.call(&mallory(), move |p| p.escape_exit(0, note, sig, alice(), U128(0)));
    assert_eq!(h.transfers, vec![(alice(), NEAR - EXIT_STORAGE_FEE)]);
}

#[test]
fn a_withdrawn_request_keeps_its_first_date() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 1, &alice());
    request(&mut h, &notes[0], &alice());
    h.now += 6 * DAY_NS;
    let nf = b64(&nullifier(0, &notes[0].token));
    h.call(&alice(), move |p| p.cancel_exit_request(0, nf));
    request(&mut h, &notes[0], &alice());
    h.sync(0, 0);
    h.now += DAY_NS;
    // Seven days after the first request, not after the second.
    let (note, sig) = (input(&notes[0]), signed(&notes[0], 0, &alice(), 0));
    h.call(&mallory(), move |p| p.escape_exit(0, note, sig, alice(), U128(0)));
}

#[test]
fn sixty_four_small_notes_of_one_account_do_not_block_the_vault() {
    let mut h = H::new();
    let small = acc("small.test");
    let notes = h.enter(0, 0, 64, &small);
    for n in &notes[..4] {
        request(&mut h, n, &small);
    }
    for n in &notes[4..8] {
        let (note, sig, to) = (input(n), signed(n, 0, &small, 0), small.clone());
        let e = h.refused_paying(&small, REQUEST_STORAGE_FEE, move |p| p.request_exit(0, note, sig, to, U128(0)));
        assert!(e.contains("too many exit requests for this account"), "{e}");
    }
    assert_eq!(h.vault(0).requests, 4);
    // Others can still ask, and the agent can still place.
    let other = h.enter(0, 0, 1, &bob());
    request(&mut h, &other[0], &bob());
    h.place(0, NEAR);
}

#[test]
fn the_agent_cannot_unstake_while_the_escape_is_open() {
    let mut h = H::new();
    h.enter(0, 1, 1, &alice());
    h.place(0, 10 * NEAR);
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    let e = h.refused(&agent(), |p| p.unstake(0, U128(NEAR)));
    assert!(e.contains("the escape is open on this vault"), "{e}");
    h.call(&mallory(), |p| p.unstake(0, U128(NEAR)));
}

#[test]
fn a_late_sync_answer_does_not_overwrite_the_balance() {
    let mut h = H::new();
    h.enter(0, 1, 1, &alice());
    h.call(&agent(), |p| p.sync(0));
    let stale = h.vault(0).busy_op;
    h.now += BUSY_TIMEOUT_NS;
    h.place(0, 10 * NEAR);
    h.callback(PromiseResult::Successful(b"\"0\"".to_vec()), |p| p.on_sync(0, stale));
    assert_eq!(h.vault(0).placed.0, 10 * NEAR);
}

#[test]
fn unstake_is_limited_to_once_per_interval_per_vault() {
    let mut h = H::new();
    h.enter(0, 1, 1, &alice());
    h.place(0, 10 * NEAR);
    h.call(&agent(), |p| p.unstake(0, U128(NEAR)));
    h.reply(0, PromiseResult::Successful(vec![]), |p, op| p.on_done(0, op));
    let e = h.refused(&agent(), |p| p.unstake(0, U128(NEAR)));
    assert!(e.contains("unstaked too recently"), "{e}");
    h.now += UNSTAKE_INTERVAL_NS;
    h.call(&agent(), |p| p.unstake(0, U128(NEAR)));
}

#[test]
fn a_late_callback_does_not_free_the_operation_that_replaced_it() {
    let mut h = H::new();
    h.enter(0, 1, 1, &alice());
    h.call(&agent(), |p| p.place(0, U128(NEAR)));
    let first = h.vault(0).busy_op;
    h.now += BUSY_TIMEOUT_NS;
    h.call(&agent(), |p| p.sync(0));
    // The placement's callback arrives late: the vault stays busy with the sync.
    h.callback(PromiseResult::Successful(vec![]), |p| p.on_place(0, U128(NEAR), first));
    assert!(h.vault(0).busy);
    let e = h.refused(&agent(), |p| p.sync(0));
    assert!(e.contains("still running"), "{e}");
}

#[test]
fn escape_exits_have_their_own_hourly_window() {
    let mut h = H::with(None, 1_000 * NEAR, 2 * NEAR);
    let notes = h.enter(0, 0, 4, &alice());
    pay(&mut h, &notes[0], &alice());
    pay(&mut h, &notes[1], &alice());
    let sig = signed(&notes[2], 0, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), &notes[2], 0, sig, &alice());
    assert!(e.contains("hourly limit reached"), "{e}");
    // A guardian announcement opens the escape in the same hour; normal exits did not use up its window.
    h.call(&guardian(), |p| p.set_fee_bps(0));
    h.call(&guardian(), |p| p.set_agent(agent()));
    for n in &notes[2..] {
        let (note, sig) = (input(n), signed(n, 0, &alice(), 0));
        h.call(&mallory(), move |p| p.escape_exit(0, note, sig, alice(), U128(0)));
    }
}

#[test]
fn the_escape_delay_is_configurable_within_bounds() {
    let h = H::with(Some(600), 1_000 * NEAR, 1_000 * NEAR);
    let mut h = h;
    assert_eq!(h.view(|p| p.get_config().escape_delay_ns), 600_000_000_000);
    h.now += 600_000_000_000;
    assert!(h.view(|p| p.escape_open()));

    context(&acc("deployer.test"), NEAR, 0, 0);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(|| Pool::new(guardian(), agent(), NETWORK.into(), Some(1), None));
    let s = catch_unwind(|| Pool::new(guardian(), agent(), NETWORK.into(), None, Some(31 * 86_400)));
    std::panic::set_hook(hook);
    assert!(panic_text(r.err().unwrap()).contains("escape delay must be between one minute and 30 days"));
    assert!(panic_text(s.err().unwrap()).contains("admin delay must be between 7 and 30 days"));
}

#[test]
fn a_returned_exit_is_kept_for_its_holder() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 1, &alice());
    pay(&mut h, &notes[0], &alice());
    let amount = NEAR - EXIT_STORAGE_FEE;
    h.balance += amount;
    h.callback(PromiseResult::Failed, |p| p.on_exit_payout(alice(), U128(amount)));
    assert_eq!(h.holder(&alice()).owed.0, amount);
    h.transfers.clear();
    h.call(&alice(), |p| p.claim_owed());
    assert_eq!(h.transfers, vec![(alice(), amount)]);
    let e = h.refused(&alice(), |p| p.claim_owed());
    assert!(e.contains("nothing owed"), "{e}");
}

// ---- plafonds ----

#[test]
fn placements_and_exits_have_separate_hourly_limits_per_vault() {
    let mut h = H::with(None, 1_000 * NEAR, 3 * NEAR);
    let notes = h.enter(0, 0, 7, &alice());
    h.place(0, 3 * NEAR);
    let e = h.refused(&agent(), |p| p.place(0, U128(NEAR)));
    assert!(e.contains("hourly limit reached"), "{e}");
    // Placing up to the limit does not hold up exits.
    for n in &notes[..3] {
        pay(&mut h, n, &alice());
    }
    let sig = signed(&notes[3], 0, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), &notes[3], 0, sig, &alice());
    assert!(e.contains("hourly limit reached"), "{e}");
    h.now += HOUR_NS;
    pay(&mut h, &notes[3], &alice());
    // Vault 1 has its own windows.
    h.enter(1, 0, 3, &bob());
    h.place(1, 3 * NEAR);
}

#[test]
fn a_vault_has_a_cap_on_its_assets() {
    let mut h = H::with(None, 5 * NEAR, 1_000 * NEAR);
    h.enter(0, 0, 5, &alice());
    h.deposit(&alice(), NEAR);
    let e = h.refused(&agent(), |p| {
        p.record_entry(0, 0, 1);
    });
    assert!(e.contains("vault cap reached"), "{e}");
}

#[test]
fn each_account_exits_at_most_its_deposits_plus_gains() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 2, &alice());
    // Bob's notes, credited to bob, are presented for alice.
    let bobs = h.enter(0, 0, 1, &bob());
    pay(&mut h, &notes[0], &alice());
    pay(&mut h, &notes[1], &alice());
    assert_eq!(h.holder(&alice()).exit_limit.0, 0);
    let sig = signed(&bobs[0], 0, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), &bobs[0], 0, sig, &alice());
    assert!(e.contains("over this account's exit limit"), "{e}");
}

#[test]
fn gains_raise_the_exit_limit_by_the_best_growth_of_any_vault() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 2, &alice());
    h.place(0, 2 * NEAR);
    h.sync(0, 2 * NEAR + NEAR / 5);
    assert_eq!(h.holder(&alice()).exit_limit.0, 2 * NEAR + NEAR / 5);
    h.withdraw(0, 2 * NEAR + NEAR / 5);
    pay(&mut h, &notes[0], &alice());
    pay(&mut h, &notes[1], &alice());
    assert_eq!(h.holder(&alice()).exit_limit.0, 0);
}

#[test]
fn a_vault_worth_nothing_blocks_no_one_else() {
    let mut h = H::new();
    let lost = h.enter(1, 0, 1, &bob());
    let notes = h.enter(0, 0, 1, &alice());
    h.place(1, NEAR);
    h.sync(1, 0);
    assert_eq!(h.vault(1).share_price.0, 0);
    // Limits still compute, entries into the empty vault stop, and other vaults still pay.
    let limit = h.holder(&alice()).exit_limit.0;
    assert_eq!(limit, NEAR * (INITIAL_PRICE / PRICE_FLOOR), "the low price is floored");
    h.deposit(&bob(), NEAR);
    let e = h.refused(&agent(), |p| {
        p.record_entry(1, 0, 1);
    });
    assert!(e.contains("share price too low"), "{e}");
    pay(&mut h, &notes[0], &alice());
    // A note of the empty vault is refused as worthless, by the agent or through the escape.
    let sig = signed(&lost[0], 1, &bob(), 0);
    let e = refused_exit(&mut h, &agent(), &lost[0], 1, sig, &bob());
    assert!(e.contains("note worth too little"), "{e}");
    h.now += 2 * DEFAULT_ESCAPE_DELAY_NS;
    let (note, sig) = (input(&lost[0]), signed(&lost[0], 1, &bob(), 0));
    let e = h.refused(&mallory(), move |p| p.escape_exit(1, note, sig, bob(), U128(0)));
    assert!(e.contains("note worth too little"), "{e}");
    assert_eq!(h.holder(&bob()).deposited.0, 2 * NEAR);
}

#[test]
fn a_frozen_vault_takes_nothing_new_but_still_pays_out() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 1, &alice());
    h.call(&guardian(), |p| p.freeze_vault(0));
    h.deposit(&alice(), NEAR);
    let e = h.refused(&agent(), |p| {
        p.record_entry(0, 0, 1);
    });
    assert!(e.contains("vault frozen"), "{e}");
    let e = h.refused(&agent(), |p| p.place(0, U128(NEAR)));
    assert!(e.contains("vault frozen"), "{e}");
    pay(&mut h, &notes[0], &alice());
}

// ---- changer de vault ----

/// Written from the SPEC, independently of the contract.
fn switch_digest_spec(from: u32, nf: &[u8; 32], to_vault: u32, outputs: &[(u8, u64)]) -> [u8; 32] {
    let mut parts: Vec<Vec<u8>> = vec![
        b"ONA-POOL-SWITCH-V1".to_vec(),
        sha(&[contract().as_bytes()]).to_vec(),
        from.to_le_bytes().to_vec(),
        nf.to_vec(),
        to_vault.to_le_bytes().to_vec(),
        (outputs.len() as u32).to_le_bytes().to_vec(),
    ];
    for (tier, count) in outputs {
        parts.push(vec![*tier]);
        parts.push(count.to_le_bytes().to_vec());
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    sha(&refs)
}

fn outs(list: &[(u8, u64)]) -> Vec<SwitchOut> {
    list.iter().map(|(tier, count)| SwitchOut { tier: *tier, count: *count }).collect()
}

fn switch_sig(n: &Note, to_vault: u32, list: &[(u8, u64)]) -> Base64VecU8 {
    b64(&sign_digest(&n.owner, &switch_digest_spec(n.vault, &nullifier(n.vault, &n.token), to_vault, list)))
}

fn switch(h: &mut H, n: &Note, to_vault: u32, list: &[(u8, u64)]) -> u128 {
    let (note, sig, o, from) = (input(n), switch_sig(n, to_vault, list), outs(list), n.vault);
    h.call(&agent(), move |p| p.switch_vault(from, note, sig, to_vault, o)).0
}

fn refused_switch(h: &mut H, n: &Note, to_vault: u32, signed_for: &[(u8, u64)], sent: &[(u8, u64)]) -> String {
    let (note, sig, o, from) = (input(n), switch_sig(n, to_vault, signed_for), outs(sent), n.vault);
    h.refused(&agent(), move |p| {
        p.switch_vault(from, note, sig, to_vault, o);
    })
}

#[test]
fn a_switch_keeps_the_value_and_pays_no_one() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 1, &alice()); // 10 NEAR in vault 0
    h.enter(1, 0, 1, &bob()); // vault 1 already has a holder
    let before = h.holder(&alice());
    h.transfers.clear();
    h.calls.clear();
    let moved = switch(&mut h, &notes[0], 1, &[(0, 10)]);
    assert_eq!(moved, 10 * NEAR, "ten 1-NEAR notes for one 10-NEAR note");
    assert!(h.transfers.is_empty() && h.calls.is_empty(), "nothing is paid and nothing leaves the pool");
    let after = h.holder(&alice());
    assert_eq!(
        (after.deposited.0, after.withdrawn.0, after.refunded.0, after.exit_limit.0),
        (before.deposited.0, before.withdrawn.0, before.refunded.0, before.exit_limit.0),
        "the account's counters do not change"
    );
    let (a, b) = (h.vault(0), h.vault(1));
    assert_eq!((a.owes.0, b.due.0), (10 * NEAR, 10 * NEAR));
    assert_eq!((a.total_shares.0, b.share_price.0), (0, INITIAL_PRICE), "prices are unchanged");
    assert_eq!(b.tiers[0].issued, 11);
}

#[test]
fn the_new_notes_cannot_be_worth_more_and_the_rest_goes_to_the_reserve() {
    let mut h = H::new();
    let notes = h.enter(0, 0, 2, &alice());
    h.place(0, 2 * NEAR);
    h.sync(0, 2 * NEAR + NEAR / 5); // 1.1 NEAR a note in vault 0
    let e = refused_switch(&mut h, &notes[0], 1, &[(0, 2)], &[(0, 2)]);
    assert!(e.contains("worth more than the note"), "{e}");
    let limit = h.holder(&alice()).exit_limit.0;
    let moved = switch(&mut h, &notes[0], 1, &[(0, 1)]);
    assert_eq!(moved, NEAR);
    // The 0.1 NEAR left over goes to the reserve: no price jumps, so no exit limit grows.
    assert_eq!(h.vault(0).share_price.0, INITIAL_PRICE / 10 * 11);
    assert_eq!(h.view(|p| p.get_debt(0, SWITCH_RESERVE)).0, NEAR / 10);
    assert_eq!(h.holder(&alice()).exit_limit.0, limit);
}

#[test]
fn a_switch_cannot_leave_more_than_one_small_note_over() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 1, &alice()); // one 10-NEAR note
    let e = refused_switch(&mut h, &notes[0], 1, &[(0, 1)], &[(0, 1)]);
    assert!(e.contains("too much left over"), "{e}");
    assert_eq!(switch(&mut h, &notes[0], 1, &[(0, 10)]), 10 * NEAR);
}

#[test]
fn debts_are_kept_per_pair_of_vaults() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 1, &alice());
    switch(&mut h, &notes[0], 1, &[(1, 1)]);
    let e = h.refused(&agent(), |p| p.settle_switch(1, 0, U128(NEAR)));
    assert!(e.contains("owes nothing"), "{e}");
    let e = h.refused(&agent(), |p| p.settle_switch(0, SWITCH_RESERVE, U128(1)));
    assert!(e.contains("owes nothing"), "{e}");
    assert_eq!(h.view(|p| p.get_debt(0, 1)).0, 10 * NEAR);
}

#[test]
fn a_vault_owing_switched_value_must_settle_before_placing() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 2, &alice());
    switch(&mut h, &notes[0], 1, &[(1, 1)]);
    let e = h.refused(&agent(), |p| p.place(0, U128(NEAR)));
    assert!(e.contains("settle switches out of this vault first"), "{e}");
    h.call(&agent(), |p| p.settle_switch(0, 1, U128(10 * NEAR)));
    h.place(0, NEAR);
}

#[test]
fn an_overdue_creditor_opens_the_vault_that_owes_it() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 1, &alice());
    h.place(0, 10 * NEAR); // the money sits in vault 0's target
    switch(&mut h, &notes[0], 1, &[(1, 1)]);
    let new_note = h.note(1, 1);
    request(&mut h, &new_note, &alice());
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, 10 * NEAR);
    }
    assert!(!h.view(|p| p.escape_open()));
    // Vault 1 is overdue and vault 0 owes it: vault 0's funds can be brought back by anyone, not the agent.
    let e = h.refused(&agent(), |p| p.unstake(0, U128(10 * NEAR)));
    assert!(e.contains("the escape is open on this vault"), "{e}");
    h.call(&mallory(), |p| p.unstake(0, U128(10 * NEAR)));
    h.reply(0, PromiseResult::Successful(vec![]), |p, op| p.on_done(0, op));
    h.call(&mallory(), |p| p.withdraw(0, U128(10 * NEAR)));
    h.balance += 10 * NEAR;
    h.reply(0, PromiseResult::Successful(vec![]), |p, op| p.on_withdraw(0, U128(10 * NEAR), op));
    h.call(&mallory(), |p| p.settle_switch(0, 1, U128(10 * NEAR)));
    let (note, sig) = (input(&new_note), signed(&new_note, 1, &alice(), 0));
    h.call(&mallory(), move |p| p.escape_exit(1, note, sig, alice(), U128(0)));
}

#[test]
fn a_new_holder_never_pays_the_debt_of_an_emptied_vault() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 1, &alice()); // alice is vault 0's only holder
    h.place(0, 10 * NEAR);
    switch(&mut h, &notes[0], 1, &[(1, 1)]); // vault 0 now owes vault 1 10 NEAR and has no shares
    h.sync(0, 9 * NEAR); // vault 0 loses 1 NEAR
    assert_eq!(h.vault(0).share_price.0, INITIAL_PRICE, "an empty vault shows the initial price");
    h.deposit(&bob(), 10 * NEAR);
    let e = h.refused(&agent(), |p| {
        p.record_entry(0, 1, 1);
    });
    assert!(e.contains("this vault owes more than it holds"), "{e}");
    // Nor can a switch bring value into it.
    let others = h.enter(1, 1, 1, &bob());
    let e = refused_switch(&mut h, &others[0], 0, &[(1, 1)], &[(1, 1)]);
    assert!(e.contains("this vault owes more than it holds"), "{e}");
}

#[test]
fn an_overdue_vault_opens_nothing_on_a_vault_that_owes_it_nothing() {
    let mut h = H::new();
    h.enter(0, 1, 1, &alice());
    h.place(0, 10 * NEAR);
    let other = h.enter(1, 1, 1, &bob());
    request(&mut h, &other[0], &bob());
    for _ in 0..7 {
        h.now += DAY_NS;
        h.sync(0, 10 * NEAR);
    }
    assert!(!h.view(|p| p.escape_open()));
    let e = h.refused(&mallory(), |p| p.unstake(0, U128(NEAR)));
    assert!(e.contains("only the agent while it is active"), "{e}");
    let e = h.refused(&mallory(), |p| p.withdraw(0, U128(NEAR)));
    assert!(e.contains("only the agent while it is active"), "{e}");
    // Vault 1 itself is open.
    h.call(&mallory(), |p| p.sync(1));
}

#[test]
fn notes_received_by_a_switch_are_valued_at_the_price_rounded_up() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 1, &alice());
    h.enter(1, 0, 1, &bob());
    h.place(1, NEAR);
    h.sync(1, NEAR + 1); // vault 1's price is 10^18 + 10^-6 yocto a share
    assert_eq!(switch(&mut h, &notes[0], 1, &[(0, 9)]), 9 * (NEAR + 1_000_000));
}

#[test]
fn deposits_and_switches_count_the_same_against_a_vault_cap() {
    let mut h = H::with(None, 10 * NEAR, 1_000 * NEAR);
    let notes = h.enter(0, 1, 1, &alice());
    switch(&mut h, &notes[0], 1, &[(1, 1)]);
    h.deposit(&bob(), NEAR);
    let e = h.refused(&agent(), |p| {
        p.record_entry(1, 0, 1);
    });
    assert!(e.contains("vault cap reached"), "{e}");
    let more = h.enter(0, 0, 1, &bob());
    let e = refused_switch(&mut h, &more[0], 1, &[(0, 1)], &[(0, 1)]);
    assert!(e.contains("vault cap reached"), "{e}");
}

#[test]
fn a_switched_note_cannot_be_spent_again() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 1, &alice());
    switch(&mut h, &notes[0], 1, &[(1, 1)]);
    let e = refused_switch(&mut h, &notes[0], 1, &[(1, 1)], &[(1, 1)]);
    assert!(e.contains("note already spent"), "{e}");
    let sig = signed(&notes[0], 0, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), &notes[0], 0, sig, &alice());
    assert!(e.contains("note already spent"), "{e}");
}

#[test]
fn a_switch_goes_only_to_a_listed_active_vault_with_the_owners_consent() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 1, &alice());
    let n = &notes[0];
    let e = refused_switch(&mut h, n, 9, &[(0, 1)], &[(0, 1)]);
    assert!(e.contains("unknown vault"), "{e}");
    let e = refused_switch(&mut h, n, 0, &[(0, 1)], &[(0, 1)]);
    assert!(e.contains("choose another vault"), "{e}");
    let fresh = h.add_vault(1_000 * NEAR, 1_000 * NEAR);
    let e = refused_switch(&mut h, n, fresh, &[(0, 1)], &[(0, 1)]);
    assert!(e.contains("vault not active yet"), "{e}");
    // The agent cannot change what the owner signed for.
    let e = refused_switch(&mut h, n, 1, &[(0, 1)], &[(1, 1)]);
    assert!(e.contains("bad owner signature"), "{e}");
    // Only the agent submits it.
    let (note, sig, o) = (input(n), switch_sig(n, 1, &[(0, 1)]), outs(&[(0, 1)]));
    let e = h.refused(&alice(), move |p| {
        p.switch_vault(0, note, sig, 1, o);
    });
    assert!(e.contains("only the agent"), "{e}");
}

#[test]
fn switched_notes_exit_from_the_new_vault_after_settlement_within_the_same_limit() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 1, &alice());
    switch(&mut h, &notes[0], 1, &[(1, 1)]);
    let new_note = h.note(1, 1);
    // Before settlement the new vault has no liquid funds to pay with.
    let sig = signed(&new_note, 1, &alice(), 0);
    let e = refused_exit(&mut h, &agent(), &new_note, 1, sig, &alice());
    assert!(e.contains("not enough liquid funds"), "{e}");
    let e = h.refused(&mallory(), |p| p.settle_switch(0, 1, U128(NEAR)));
    assert!(e.contains("only the agent while it is active"), "{e}");
    let e = h.refused(&agent(), |p| p.settle_switch(0, 1, U128(11 * NEAR)));
    assert!(e.contains("more than is owed"), "{e}");
    h.call(&agent(), |p| p.settle_switch(0, 1, U128(10 * NEAR)));
    let (a, b) = (h.vault(0), h.vault(1));
    assert_eq!((a.owes.0, a.liquid.0, b.due.0, b.liquid.0), (0, 0, 0, 10 * NEAR));
    h.transfers.clear();
    pay(&mut h, &new_note, &alice());
    assert_eq!(h.transfers, vec![(alice(), 10 * NEAR - EXIT_STORAGE_FEE)]);
    assert_eq!(h.holder(&alice()).exit_limit.0, 0, "a switch never raised the limit");
}

#[test]
fn a_note_with_a_pending_request_cannot_be_switched_and_the_escape_keeps_working() {
    let mut h = H::new();
    let notes = h.enter(0, 1, 2, &alice());
    request(&mut h, &notes[0], &alice());
    let e = refused_switch(&mut h, &notes[0], 1, &[(1, 1)], &[(1, 1)]);
    assert!(e.contains("withdraw the exit request on this note first"), "{e}");
    let nf = b64(&nullifier(0, &notes[0].token));
    h.call(&alice(), move |p| p.cancel_exit_request(0, nf));
    switch(&mut h, &notes[0], 1, &[(1, 1)]);
    // During the escape anyone can settle, then the switched note leaves from the new vault.
    h.now += DEFAULT_ESCAPE_DELAY_NS;
    h.call(&mallory(), |p| p.settle_switch(0, 1, U128(10 * NEAR)));
    let new_note = h.note(1, 1);
    let (note, sig) = (input(&new_note), signed(&new_note, 1, &alice(), 0));
    h.call(&mallory(), move |p| p.escape_exit(1, note, sig, alice(), U128(0)));
}
