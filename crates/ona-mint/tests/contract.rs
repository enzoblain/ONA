//! Contract logic on the mocked NEAR VM, which runs the real BLS12-381 and ed25519 host functions.
//! Tokens are produced by `ona-token` (blst), so these tests also cross-check the two implementations.

use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use ed25519_dalek::SigningKey;
use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::mock::MockAction;
use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
use near_sdk::{env, testing_env, AccountId, Gas, NearToken, PromiseResult};
use ona_mint::*;
use ona_token::{
    claim_digest, hash_to_g1, keygen, redeem_digest, sign_blinded, sign_digest, spend_digest,
    token_dst, ChangeOut, PendingToken, SecretKey, Token, G1_LEN, G2_LEN,
};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MILLI: u128 = NEAR / 1000;
const UNIT: u128 = 100 * MILLI;
const NETWORK: &str = "sandbox";

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn contract() -> AccountId {
    acc("mint.test")
}
fn signer() -> AccountId {
    acc("signer.test")
}
fn relay() -> AccountId {
    acc("relay.test")
}
fn guardian() -> AccountId {
    acc("guardian.test")
}
fn alice() -> AccountId {
    acc("alice.test")
}
fn bob() -> AccountId {
    acc("bob.test")
}
fn b64(b: &[u8]) -> Base64VecU8 {
    Base64VecU8(b.to_vec())
}
fn implicit(pk: &[u8; 32]) -> AccountId {
    pk.iter().map(|b| format!("{b:02x}")).collect::<String>().parse().unwrap()
}

fn token_input(t: &Token) -> TokenInput {
    TokenInput { denom_id: t.denom_id, pk: b64(&t.pk), nonce: b64(&t.nonce), sig: b64(&t.sig) }
}

thread_local! {
    /// Owner keys by public key, so tests can redeem a token without carrying its key around.
    static OWNERS: RefCell<HashMap<[u8; 32], SigningKey>> = RefCell::new(HashMap::new());
}

/// Redeems with a signature from the token's owner, for the caller set in the mock context.
fn rd(m: &mut Mint, t: &Token) {
    let d = redeem_digest(contract().as_str(), env::predecessor_account_id().as_str(), &t.nullifier());
    let key = OWNERS.with(|o| o.borrow().get(&t.pk).cloned()).unwrap_or_else(|| SigningKey::generate(&mut OsRng));
    m.redeem(token_input(t), b64(&sign_digest(&key, &d)));
}

fn panic_text(e: Box<dyn std::any::Any + Send>) -> String {
    e.downcast_ref::<String>()
        .cloned()
        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

struct H {
    mint: Mint,
    balance: u128,
    storage: u64,
    now: u64,
    sks: Vec<SecretKey>,
    pks: Vec<[u8; G2_LEN]>,
    dst: Vec<u8>,
    surplus: i128,
    payments: Vec<(AccountId, u128)>,
}

fn context(pred: &AccountId, attached: u128, balance: u128, storage: u64, now: u64) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(contract())
        .predecessor_account_id(pred.clone())
        .signer_account_id(pred.clone())
        .attached_deposit(NearToken::from_yoctonear(attached))
        .account_balance(NearToken::from_yoctonear(balance))
        .storage_usage(storage)
        .block_timestamp(now)
        .prepaid_gas(Gas::from_tgas(1000))
        .build());
}

fn denom_inits(pks: &[[u8; G2_LEN]], cap: u64, hourly: u64) -> Vec<DenomInit> {
    pks.iter()
        .enumerate()
        .map(|(i, pk)| DenomInit {
            value: U128(UNIT << i),
            pk_g2: b64(pk),
            circulation_cap: cap,
            hourly_redeem_cap: hourly,
        })
        .collect()
}

impl H {
    fn with_limits(cap: u64, hourly: u64) -> Self {
        let sks: Vec<SecretKey> = (0..4).map(|_| keygen(&mut OsRng)).collect();
        let pks: Vec<[u8; G2_LEN]> = sks.iter().map(|k| k.public_key()).collect();
        let balance = 50 * NEAR;
        let now = 1_000 * HOUR_NS;
        context(&acc("deployer.test"), 0, balance, 0, now);
        let mint = Mint::new(denom_inits(&pks, cap, hourly), signer(), relay(), guardian(), NETWORK.into());
        let storage = env::storage_usage();
        let mut h = Self {
            mint,
            balance,
            storage,
            now,
            sks,
            pks,
            dst: token_dst(NETWORK, contract().as_str()).unwrap(),
            surplus: 0,
            payments: Vec::new(),
        };
        h.surplus = h.current_surplus();
        h
    }

    fn new() -> Self {
        Self::with_limits(1_000, 1_000)
    }

    fn current_surplus(&mut self) -> i128 {
        context(&alice(), 0, self.balance, self.storage, self.now);
        let s = self.mint.reserve_status();
        s.balance.0 as i128 - s.storage_cost.0 as i128 - s.liabilities.0 as i128
    }

    /// Runs one method, applies its transfers, and checks invariant I1: the margin of the balance
    /// over storage and liabilities is positive and never shrinks.
    fn call<R>(&mut self, pred: &AccountId, attached: u128, f: impl FnOnce(&mut Mint) -> R) -> R {
        self.balance += attached;
        context(pred, attached, self.balance, self.storage, self.now);
        let r = f(&mut self.mint);
        self.storage = env::storage_usage();
        for receipt in get_created_receipts() {
            for action in receipt.actions {
                if let MockAction::Transfer { deposit, .. } = action {
                    self.balance -= deposit.as_yoctonear();
                    self.payments.push((receipt.receiver_id.clone(), deposit.as_yoctonear()));
                }
            }
        }
        let surplus = self.current_surplus();
        assert!(surplus >= 0, "I1 broken: margin {surplus}");
        assert!(surplus >= self.surplus, "I1 broken: margin fell from {} to {surplus}", self.surplus);
        self.surplus = surplus;
        r
    }

    /// Runs a call expected to panic and returns its message. Storage is not rolled back by the
    /// mock, so callers only use this for refusals that happen before any write, or stop after.
    fn refused(&mut self, pred: &AccountId, attached: u128, f: impl FnOnce(&mut Mint)) -> String {
        context(pred, attached, self.balance + attached, self.storage, self.now);
        let mint = &mut self.mint;
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = catch_unwind(AssertUnwindSafe(|| f(mint)));
        std::panic::set_hook(hook);
        panic_text(result.expect_err("the call should have been refused"))
    }

    fn cost(&self, denom: u8, n: u128) -> u128 {
        n * ((UNIT << denom) + STORAGE_PER_TOKEN + ISSUE_FEE_PER_TOKEN) + NEAR / 10
    }

    fn deposit(&mut self, denom: u8, n: usize) -> (u64, Vec<PendingToken>) {
        let dst = self.dst.clone();
        let tokens: Vec<_> =
            (0..n).map(|_| PendingToken::new(&mut OsRng, denom, &dst).unwrap()).collect();
        let blinded: Vec<_> = tokens.iter().map(|t| b64(&t.blinded)).collect();
        let cost = self.cost(denom, n as u128);
        let U64(id) = self.call(&alice(), cost, |m| m.deposit(denom, blinded));
        (id, tokens)
    }

    fn sign(&self, denom: u8, tokens: &[PendingToken]) -> Vec<[u8; G1_LEN]> {
        tokens.iter().map(|t| sign_blinded(&self.sks[denom as usize], &t.blinded).unwrap()).collect()
    }

    fn mint_tokens(&mut self, denom: u8, n: usize) -> Vec<(Token, SigningKey)> {
        let (id, pending) = self.deposit(denom, n);
        let sigs = self.sign(denom, &pending);
        let args: Vec<_> = sigs.iter().map(|s| b64(s)).collect();
        self.lock_and_issue(id, args);
        let pk = self.pks[denom as usize];
        let minted: Vec<(Token, SigningKey)> =
            pending.into_iter().zip(sigs).map(|(p, s)| p.finish(&s, &pk).unwrap()).collect();
        OWNERS.with(|o| {
            for (t, k) in &minted {
                o.borrow_mut().insert(t.pk, k.clone());
            }
        });
        minted
    }

    fn lock_and_issue(&mut self, id: u64, sigs: Vec<Base64VecU8>) {
        self.call(&signer(), 0, |m| m.lock(U64(id)));
        self.call(&signer(), 0, |m| m.issue(U64(id), sigs));
    }

    /// Delivers the result of a `spend` transfer to its callback.
    fn payout_callback(&mut self, result: PromiseResult, owner: AccountId, amount: u128) {
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
        self.mint.on_spend_payout(owner, U128(amount));
        for receipt in get_created_receipts() {
            for action in receipt.actions {
                if let MockAction::Transfer { deposit, .. } = action {
                    self.balance -= deposit.as_yoctonear();
                    self.payments.push((receipt.receiver_id.clone(), deposit.as_yoctonear()));
                }
            }
        }
    }

    fn mint_one(&mut self, denom: u8) -> (Token, SigningKey) {
        self.mint_tokens(denom, 1).pop().unwrap()
    }

    fn lock_and_issue_with_one(&mut self, id: u64, sig: &[u8; G1_LEN]) {
        self.lock_and_issue(id, vec![b64(sig)]);
    }

    fn counters(&mut self, denom: u8) -> Counters {
        context(&alice(), 0, self.balance, self.storage, self.now);
        self.mint.get_denom(denom).counters
    }

    fn paid_to(&self, who: &AccountId) -> u128 {
        self.payments.iter().filter(|(a, _)| a == who).map(|(_, v)| v).sum()
    }
}

struct SpendArgs {
    token: TokenInput,
    sig: Base64VecU8,
    to: AccountId,
    amount: U128,
    fee: U128,
    change: Vec<BlindedOut>,
}

fn spend_args(t: &Token, owner: &SigningKey, to: &AccountId, amount: u128, fee: u128, change: &[ChangeOut]) -> SpendArgs {
    let d = spend_digest(contract().as_str(), relay().as_str(), t.denom_id, &t.nullifier(), to.as_str(), amount, fee, change);
    SpendArgs {
        token: token_input(t),
        sig: b64(&sign_digest(owner, &d)),
        to: to.clone(),
        amount: U128(amount),
        fee: U128(fee),
        change: change.iter().map(|c| BlindedOut { denom_id: c.denom_id, blinded: b64(&c.blinded) }).collect(),
    }
}

fn do_spend(m: &mut Mint, a: SpendArgs) {
    m.spend(a.token, a.sig, a.to, a.amount, a.fee, a.change)
}

fn claim(t: &Token, owner: &SigningKey) -> ClaimInput {
    let d = claim_digest(contract().as_str(), relay().as_str(), &t.nullifier());
    ClaimInput { token: token_input(t), owner_sig: b64(&sign_digest(owner, &d)) }
}

// ---------- cross-checks with blst ----------

#[test]
fn hash_to_g1_matches_blst() {
    context(&alice(), 0, NEAR, 0, 1);
    let dst = token_dst(NETWORK, contract().as_str()).unwrap();
    for len in [0usize, 1, 64, 200] {
        let mut msg = vec![0u8; len];
        OsRng.fill_bytes(&mut msg);
        let compressed = hash_to_g1(&msg, &dst);
        let expected = ona_token::g1_to_raw(&compressed).unwrap();
        assert_eq!(hash_to_g1_raw(&msg, &dst), expected.to_vec(), "len {len}");
    }
}

#[test]
fn hash_to_g1_rfc9380_vector_via_host() {
    context(&alice(), 0, NEAR, 0, 1);
    let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let raw = hash_to_g1_raw(b"abc", dst);
    let x: String = raw[..48].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(x, "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903");
}

// ---------- happy paths ----------

#[test]
fn deposit_issue_redeem_pays_the_token_owner() {
    let mut h = H::new();
    let (t, _owner) = h.mint_one(2);
    h.call(&bob(), 0, |m| rd(m, &t));
    assert_eq!(h.paid_to(&implicit(&t.pk)), (UNIT << 2) - REDEEM_FEE);
    assert_eq!(h.paid_to(&bob()), REDEEM_FEE);
    let c = h.counters(2);
    assert_eq!((c.deposited, c.issued, c.redeemed), (1, 1, 1));
}

#[test]
fn spend_pays_recipient_and_queues_change() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(2); // 0.4 NEAR
    let dst = h.dst.clone();
    let change_token = PendingToken::new(&mut OsRng, 0, &dst).unwrap();
    let change = [ChangeOut { denom_id: 0, blinded: change_token.blinded }];
    let fee = 50 * MILLI;
    let amount = (UNIT << 2) - UNIT - fee;
    let a = spend_args(&t, &owner, &bob(), amount, fee, &change);
    h.call(&relay(), 0, |m| do_spend(m, a));

    assert_eq!(h.paid_to(&bob()), amount);
    let kept = h.paid_to(&relay());
    let change_floor = STORAGE_PER_TOKEN + ISSUE_FEE_PER_TOKEN;
    assert!(kept > 0 && kept <= fee - change_floor, "the relay keeps only what the change does not cost: {kept}");
    // Whatever the relay did not keep is what the record's storage cost.
    context(&alice(), 0, h.balance, h.storage, h.now);
    let record_total = h.mint.pending_deposits(U64(0), 10)[0].total.0;
    assert_eq!(kept, fee - (record_total - UNIT), "the fee splits exactly");

    context(&alice(), 0, h.balance, h.storage, h.now);
    let pending = h.mint.pending_deposits(U64(0), 10);
    assert_eq!(pending.len(), 1);
    assert!(pending[0].is_change);
    assert_eq!(pending[0].depositor, implicit(&t.pk));

    let sig = sign_blinded(&h.sks[0], &change_token.blinded).unwrap();
    let id = pending[0].id;
    h.lock_and_issue_with_one(id.0, &sig);
    let (ct, change_owner) = change_token.finish(&sig, &h.pks[0]).unwrap();
    OWNERS.with(|o| o.borrow_mut().insert(ct.pk, change_owner));
    h.call(&bob(), 0, |m| rd(m, &ct));
    assert_eq!(h.paid_to(&implicit(&ct.pk)), UNIT - REDEEM_FEE);
}

#[test]
fn relay_claim_collects_and_skips_bad_items() {
    let mut h = H::new();
    let (t1, o1) = h.mint_one(0);
    let (t2, o2) = h.mint_one(0);
    let (t3, _o3) = h.mint_one(0);
    let wrong_owner = SigningKey::generate(&mut OsRng);
    let mut garbled = claim(&t2, &o2);
    garbled.token.sig = Base64VecU8(vec![0xff; 48]);
    let items = vec![
        claim(&t1, &o1),
        claim(&t1, &o1), // duplicate within the call
        garbled,
        claim(&t3, &wrong_owner),
        claim(&t2, &o2),
    ];
    let result = h.call(&relay(), 0, |m| m.relay_claim(items));
    assert_eq!(result, vec![true, false, false, false, true]);
    assert_eq!(h.paid_to(&relay()), 2 * UNIT);
}

#[test]
fn signer_collects_fees() {
    let mut h = H::new();
    h.mint_tokens(0, 4);
    h.call(&signer(), 0, |m| m.claim_signer_fees());
    assert_eq!(h.paid_to(&signer()), 4 * ISSUE_FEE_PER_TOKEN);
    h.call(&signer(), 0, |m| m.claim_signer_fees());
    assert_eq!(h.paid_to(&signer()), 4 * ISSUE_FEE_PER_TOKEN, "fees are paid once");
}

#[test]
fn surplus_of_a_deposit_is_returned() {
    let mut h = H::new();
    let (_id, _t) = h.deposit(0, 1);
    let paid = h.paid_to(&alice());
    assert!(paid > 0, "the excess attached deposit comes back");
    assert!(paid < NEAR / 10);
}

// ---------- forgery ----------

#[test]
fn split_attack_on_issue_is_refused() {
    let mut h = H::new();
    let (id, pending) = h.deposit(0, 2);
    let sigs = h.sign(0, &pending);
    // Part 1 and part 2 sum to the honest aggregate, but neither is a valid signature on its own.
    let noise = hash_to_g1(b"attacker noise", &h.dst);
    let split = |s: &[u8; G1_LEN], neg: bool| {
        let mut n = noise;
        if neg {
            n[0] ^= 0x20;
        }
        add_g1(s, &n)
    };
    let args = vec![b64(&split(&sigs[0], false)), b64(&split(&sigs[1], true))];
    h.call(&signer(), 0, |m| m.lock(U64(id)));
    let msg = h.refused(&signer(), 0, |m| m.issue(U64(id), args));
    assert!(msg.contains("bad signature"), "{msg}");
}

fn add_g1(a: &[u8; G1_LEN], b: &[u8; G1_LEN]) -> [u8; G1_LEN] {
    use blst::*;
    let (mut pa, mut pb) = (blst_p1_affine::default(), blst_p1_affine::default());
    let (mut ja, mut sum, mut af) = (blst_p1::default(), blst_p1::default(), blst_p1_affine::default());
    let mut out = [0u8; G1_LEN];
    unsafe {
        assert_eq!(blst_p1_uncompress(&mut pa, a.as_ptr()), BLST_ERROR::BLST_SUCCESS);
        assert_eq!(blst_p1_uncompress(&mut pb, b.as_ptr()), BLST_ERROR::BLST_SUCCESS);
        blst_p1_from_affine(&mut ja, &pa);
        blst_p1_add_or_double_affine(&mut sum, &ja, &pb);
        blst_p1_to_affine(&mut af, &sum);
        blst_p1_affine_compress(out.as_mut_ptr(), &af);
    }
    out
}

fn non_subgroup_g1() -> [u8; G1_LEN] {
    use blst::*;
    for x in 1u32.. {
        let mut c = [0u8; G1_LEN];
        c[44..].copy_from_slice(&x.to_be_bytes());
        c[0] = 0x80;
        let mut a = blst_p1_affine::default();
        let ok = unsafe { blst_p1_uncompress(&mut a, c.as_ptr()) } == BLST_ERROR::BLST_SUCCESS;
        if ok && !unsafe { blst_p1_affine_in_g1(&a) } {
            return c;
        }
    }
    unreachable!()
}

fn non_subgroup_g2() -> [u8; G2_LEN] {
    use blst::*;
    for x in 1u32.. {
        let mut c = [0u8; G2_LEN];
        c[47] = 1;
        c[92..].copy_from_slice(&x.to_be_bytes());
        c[0] = 0x80;
        let mut a = blst_p2_affine::default();
        let ok = unsafe { blst_p2_uncompress(&mut a, c.as_ptr()) } == BLST_ERROR::BLST_SUCCESS;
        if ok && !unsafe { blst_p2_affine_in_g2(&a) } {
            return c;
        }
    }
    unreachable!()
}

#[test]
fn forged_tokens_are_refused() {
    let mut h = H::new();
    let (t, _) = h.mint_one(1);

    let mut bad = t.clone();
    bad.nonce[0] ^= 1;
    let msg = h.refused(&bob(), 0, |m| rd(m, &bad));
    assert!(msg.contains("invalid token"), "{msg}");

    let mut bad = t.clone();
    bad.pk[5] ^= 1;
    let msg = h.refused(&bob(), 0, |m| rd(m, &bad));
    assert!(msg.contains("bad owner signature"), "another owner key: {msg}");

    let mut wrong_tier = t.clone();
    wrong_tier.denom_id = 3;
    let msg = h.refused(&bob(), 0, |m| rd(m, &wrong_tier));
    assert!(msg.contains("invalid token"), "a token of one tier cannot claim another: {msg}");

    let mut other_sig = t.clone();
    other_sig.sig = non_subgroup_g1();
    let msg = h.refused(&bob(), 0, |m| rd(m, &other_sig));
    assert!(msg.contains("invalid token"), "non-subgroup signature: {msg}");

    let mut inf = t.clone();
    inf.sig = [0u8; G1_LEN];
    inf.sig[0] = 0xc0;
    let msg = h.refused(&bob(), 0, |m| rd(m, &inf));
    assert!(msg.contains("invalid token"), "infinity: {msg}");

    let mut short = token_input(&t);
    short.sig = b64(&[1, 2, 3]);
    let msg = h.refused(&bob(), 0, |m| m.redeem(short, b64(&[0; 64])));
    assert!(msg.contains("bad token encoding"), "{msg}");

    let unknown = TokenInput { denom_id: 200, ..token_input(&t) };
    let msg = h.refused(&bob(), 0, |m| m.redeem(unknown, b64(&[0; 64])));
    assert!(msg.contains("unknown denomination"), "{msg}");
}

#[test]
fn redeem_needs_the_owner_and_names_the_submitter() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(1);
    let msg = h.refused(&bob(), 0, |m| m.redeem(token_input(&t), b64(&[0; 10])));
    assert!(msg.contains("owner signature length"), "{msg}");

    let thief = SigningKey::generate(&mut OsRng);
    let d = redeem_digest(contract().as_str(), bob().as_str(), &t.nullifier());
    let forged = b64(&sign_digest(&thief, &d));
    let msg = h.refused(&bob(), 0, |m| m.redeem(token_input(&t), forged));
    assert!(msg.contains("bad owner signature"), "someone who only saw the token: {msg}");

    let for_bob = b64(&sign_digest(&owner, &d));
    let replay = for_bob.clone();
    let msg = h.refused(&alice(), 0, |m| m.redeem(token_input(&t), replay));
    assert!(msg.contains("bad owner signature"), "signature made for another submitter: {msg}");

    h.call(&bob(), 0, |m| m.redeem(token_input(&t), for_bob));
    assert_eq!(h.paid_to(&bob()), REDEEM_FEE);
}

#[test]
fn a_cheap_tier_cannot_burn_an_expensive_token() {
    let mut h = H::new();
    let (expensive, _) = h.mint_one(3);
    // A second token with the same owner and nonce, signed on tier 0 by a blind signer.
    let cheap_message = {
        let mut m = expensive.message();
        m[0] = 0;
        m
    };
    let point = hash_to_g1(&cheap_message, &h.dst);
    let cost = h.cost(0, 1);
    let U64(id) = h.call(&alice(), cost, |m| m.deposit(0, vec![b64(&point)]));
    let direct = sign_blinded(&h.sks[0], &point).unwrap();
    h.lock_and_issue_with_one(id, &direct);
    let cheap = Token { denom_id: 0, pk: expensive.pk, nonce: expensive.nonce, sig: direct };
    h.call(&bob(), 0, |m| rd(m, &cheap));
    assert_ne!(cheap.nullifier(), expensive.nullifier());
    h.call(&bob(), 0, |m| rd(m, &expensive));
    assert_eq!(h.counters(3).redeemed, 1, "the expensive token is still spendable");
}

#[test]
fn a_signature_on_a_non_subgroup_point_is_refused_even_if_correct() {
    let mut h = H::new();
    let bad = non_subgroup_g1();
    let cost = h.cost(0, 1);
    let U64(id) = h.call(&alice(), cost, |m| m.deposit(0, vec![b64(&bad)]));
    h.call(&signer(), 0, |m| m.lock(U64(id)));
    let sig = raw_mult(&bad, &h.sks[0]);
    let msg = h.refused(&signer(), 0, |m| m.issue(U64(id), vec![b64(&sig)]));
    assert!(msg.contains("bad signature"), "sk*B with B outside the subgroup: {msg}");
}

fn raw_mult(point: &[u8; G1_LEN], sk: &SecretKey) -> [u8; G1_LEN] {
    use blst::*;
    let mut le = sk.to_bytes();
    le.reverse();
    let mut a = blst_p1_affine::default();
    let (mut j, mut out, mut af) = (blst_p1::default(), blst_p1::default(), blst_p1_affine::default());
    let mut c = [0u8; G1_LEN];
    unsafe {
        assert_eq!(blst_p1_uncompress(&mut a, point.as_ptr()), BLST_ERROR::BLST_SUCCESS);
        blst_p1_from_affine(&mut j, &a);
        blst_p1_mult(&mut out, &j, le.as_ptr(), 255);
        blst_p1_to_affine(&mut af, &out);
        blst_p1_affine_compress(c.as_mut_ptr(), &af);
    }
    c
}

#[test]
fn malformed_items_never_abort_a_relay_batch() {
    let mut h = H::new();
    let (good, owner) = h.mint_one(0);
    let (other, other_owner) = h.mint_one(0);

    let mut off_curve = claim(&other, &other_owner);
    let mut x = [0xaau8; G1_LEN];
    x[0] = 0x9a; // compression flag set, not a point on the curve
    off_curve.token.sig = b64(&x);

    let mut bad_key = claim(&other, &other_owner);
    bad_key.token.pk = b64(&[0xff; 32]); // not a valid ed25519 point

    let mut short_sig = claim(&other, &other_owner);
    short_sig.owner_sig = b64(&[1, 2, 3]);

    let mut unknown_denom = claim(&other, &other_owner);
    unknown_denom.token.denom_id = 99;

    let items = vec![off_curve, bad_key, short_sig, unknown_denom, claim(&good, &owner)];
    assert_eq!(h.call(&relay(), 0, |m| m.relay_claim(items)), vec![false, false, false, false, true]);
}

#[test]
fn token_signed_for_another_contract_is_refused() {
    let mut h = H::new();
    let other_dst = token_dst(NETWORK, "other.test").unwrap();
    let p = PendingToken::new(&mut OsRng, 0, &other_dst).unwrap();
    let sig = sign_blinded(&h.sks[0], &p.blinded).unwrap();
    let (t, owner) = p.finish(&sig, &h.pks[0]).unwrap();
    OWNERS.with(|o| o.borrow_mut().insert(t.pk, owner));
    h.mint_one(0); // so that an issued token exists to be claimed against
    let msg = h.refused(&bob(), 0, |m| rd(m, &t));
    assert!(msg.contains("invalid token"), "{msg}");
}

#[test]
fn double_spend_is_refused() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(1);
    let amount = (UNIT << 1) - 20 * MILLI;
    let a = spend_args(&t, &owner, &bob(), amount, 20 * MILLI, &[]);
    h.call(&relay(), 0, |m| do_spend(m, a));

    let msg = h.refused(&bob(), 0, |m| rd(m, &t));
    assert!(msg.contains("already spent"), "{msg}");
    let a = spend_args(&t, &owner, &bob(), amount, 20 * MILLI, &[]);
    let msg = h.refused(&relay(), 0, |m| do_spend(m, a));
    assert!(msg.contains("already spent"), "{msg}");
    let items = vec![claim(&t, &owner)];
    assert_eq!(h.call(&relay(), 0, |m| m.relay_claim(items)), vec![false]);
}

// ---------- spend authorization ----------

#[test]
fn spend_fields_are_bound_to_the_owner_signature() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(1);
    let value = UNIT << 1;
    let fee = 20 * MILLI;
    let good = || spend_args(&t, &owner, &bob(), value - fee, fee, &[]);

    let mut a = good();
    a.to = acc("eve.test");
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("bad owner signature"));

    let mut a = good();
    a.amount = U128(value - fee - MILLI);
    a.fee = U128(fee + MILLI);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("bad owner signature"));

    let dst = h.dst.clone();
    let mut a = good();
    let extra = PendingToken::new(&mut OsRng, 0, &dst).unwrap();
    a.change = vec![BlindedOut { denom_id: 0, blinded: b64(&extra.blinded) }];
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("bad owner signature"));

    let thief = SigningKey::generate(&mut OsRng);
    let a = spend_args(&t, &thief, &bob(), value - fee, fee, &[]);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("bad owner signature"));

    let a = good();
    assert!(h.refused(&bob(), 0, |m| do_spend(m, a)).contains("bad owner signature"), "replay from another account to take the fee");

    let mut a = good();
    a.sig = b64(&[0u8; 10]);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("owner signature length"));

    h.call(&relay(), 0, |m| do_spend(m, good()));
    assert_eq!(h.paid_to(&bob()), value - fee);
}

#[test]
fn spend_amounts_must_balance() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(2);
    let value = UNIT << 2;
    let dst = h.dst.clone();
    let c = PendingToken::new(&mut OsRng, 0, &dst).unwrap();
    let change = [ChangeOut { denom_id: 0, blinded: c.blinded }];
    let fee = 50 * MILLI;

    let a = spend_args(&t, &owner, &bob(), value - fee, fee, &change);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("must equal"), "change on top of the full value");

    let a = spend_args(&t, &owner, &bob(), value, fee, &[]);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("must equal"), "more than the token");

    let a = spend_args(&t, &owner, &bob(), value - fee - 1, fee, &[]);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("must equal"), "value lost");

    let a = spend_args(&t, &owner, &bob(), MILLI, value - MILLI, &[]);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("too small"), "amount under the payout minimum");

    let a = spend_args(&t, &owner, &contract(), value - fee, fee, &[]);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("cannot pay the mint"));

    let many = vec![ChangeOut { denom_id: 0, blinded: c.blinded }; MAX_CHANGE + 1];
    let a = spend_args(&t, &owner, &bob(), value - fee, fee, &many);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("too many change"));
}

#[test]
fn spend_fee_must_cover_the_change_cost() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(2);
    let value = UNIT << 2;
    let dst = h.dst.clone();
    let c = PendingToken::new(&mut OsRng, 0, &dst).unwrap();
    let change = [ChangeOut { denom_id: 0, blinded: c.blinded }];
    let fee = STORAGE_PER_TOKEN + ISSUE_FEE_PER_TOKEN; // nothing left for the record's storage
    let a = spend_args(&t, &owner, &bob(), value - UNIT - fee, fee, &change);
    let msg = h.refused(&relay(), 0, |m| do_spend(m, a));
    assert!(msg.contains("does not cover"), "{msg}");
}

#[test]
fn failed_payout_goes_to_the_token_owner() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(1);
    let fee = 20 * MILLI;
    let amount = (UNIT << 1) - fee;
    let ghost = acc("ghost.test");
    let a = spend_args(&t, &owner, &ghost, amount, fee, &[]);
    h.call(&relay(), 0, |m| do_spend(m, a));

    // On NEAR the failed transfer comes back to the contract as a refund.
    h.balance += amount;
    h.payments.retain(|(who, _)| who != &ghost);
    h.payout_callback(PromiseResult::Failed, implicit(&t.pk), amount);
    assert_eq!(h.paid_to(&implicit(&t.pk)), amount);
}

#[test]
fn successful_payout_sends_nothing_more() {
    let mut h = H::new();
    h.payout_callback(PromiseResult::Successful(vec![]), bob(), UNIT);
    assert_eq!(h.paid_to(&bob()), 0);
}

#[test]
fn no_change_while_halted() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(2);
    h.call(&guardian(), 0, |m| m.halt());
    let dst = h.dst.clone();
    let c = PendingToken::new(&mut OsRng, 0, &dst).unwrap();
    let change = [ChangeOut { denom_id: 0, blinded: c.blinded }];
    let fee = 50 * MILLI;
    let a = spend_args(&t, &owner, &bob(), (UNIT << 2) - UNIT - fee, fee, &change);
    assert!(h.refused(&relay(), 0, |m| do_spend(m, a)).contains("no change while halted"));
}

// ---------- issuance control ----------

#[test]
fn a_published_signature_cannot_be_combined_with_a_refund() {
    let mut h = H::new();
    let (id, pending) = h.deposit(0, 1);
    let sigs: Vec<_> = h.sign(0, &pending).iter().map(|s| b64(s)).collect();

    let args = sigs.clone();
    assert!(h.refused(&signer(), 0, |m| m.issue(U64(id), args)).contains("not locked"), "no signature can land before the lock");

    h.call(&signer(), 0, |m| m.lock(U64(id)));
    h.now += ISSUE_TIMEOUT_NS;
    let msg = h.refused(&alice(), 0, |m| m.refund(U64(id)));
    assert!(msg.contains("deadline not reached"), "the lock holds past the original deadline: {msg}");

    h.call(&signer(), 0, |m| m.issue(U64(id), sigs));
    let msg = h.refused(&alice(), 0, |m| m.refund(U64(id)));
    assert!(msg.contains("unknown deposit"), "{msg}");
}

#[test]
fn lock_rules() {
    let mut h = H::new();
    let (id, _) = h.deposit(0, 1);
    assert!(h.refused(&bob(), 0, |m| m.lock(U64(id))).contains("only the signer"));
    h.call(&signer(), 0, |m| m.lock(U64(id)));
    assert!(h.refused(&signer(), 0, |m| m.lock(U64(id))).contains("already locked"));

    let (late, _) = h.deposit(0, 1);
    h.now += ISSUE_TIMEOUT_NS;
    assert!(h.refused(&signer(), 0, |m| m.lock(U64(late))).contains("deadline passed"));
}

#[test]
fn an_abandoned_lock_eventually_allows_a_refund() {
    let mut h = H::new();
    let (id, pending) = h.deposit(0, 1);
    let sigs: Vec<_> = h.sign(0, &pending).iter().map(|s| b64(s)).collect();
    h.call(&signer(), 0, |m| m.lock(U64(id)));
    h.now += LOCK_TIMEOUT_NS;
    assert!(h.refused(&signer(), 0, |m| m.issue(U64(id), sigs)).contains("lock expired"));
    h.call(&alice(), 0, |m| m.refund(U64(id)));
}

#[test]
fn a_halt_does_not_strand_a_locked_deposit() {
    let mut h = H::new();
    let (id, pending) = h.deposit(0, 1);
    let sigs: Vec<_> = h.sign(0, &pending).iter().map(|s| b64(s)).collect();
    h.call(&signer(), 0, |m| m.lock(U64(id)));
    h.call(&guardian(), 0, |m| m.halt());
    h.call(&signer(), 0, |m| m.issue(U64(id), sigs));
    assert_eq!(h.counters(0).issued, 1);
}

#[test]
fn issue_access_and_replay() {
    let mut h = H::new();
    let (id, pending) = h.deposit(0, 1);
    let sigs: Vec<_> = h.sign(0, &pending).iter().map(|s| b64(s)).collect();
    h.call(&signer(), 0, |m| m.lock(U64(id)));

    let args = sigs.clone();
    assert!(h.refused(&bob(), 0, |m| m.issue(U64(id), args)).contains("only the signer"));

    assert!(h.refused(&signer(), 0, |m| m.issue(U64(id), vec![])).contains("wrong signature count"));

    let wrong: Vec<_> = vec![b64(&sign_blinded(&h.sks[1], &pending[0].blinded).unwrap())];
    assert!(h.refused(&signer(), 0, |m| m.issue(U64(id), wrong)).contains("bad signature"), "signature under another tier's key");

    let args = sigs.clone();
    h.call(&signer(), 0, |m| m.issue(U64(id), args));
    assert!(h.refused(&signer(), 0, |m| m.issue(U64(id), sigs)).contains("unknown deposit"), "issue twice");
}

#[test]
fn deposit_validation() {
    let mut h = H::new();
    let dst = h.dst.clone();
    let good = || b64(&PendingToken::new(&mut OsRng, 0, &dst).unwrap().blinded);
    let cost = NEAR;

    for n in [0usize, 3, 5, 65, 128] {
        let items: Vec<_> = (0..n).map(|_| good()).collect();
        assert!(h.refused(&alice(), cost * 70, |m| { m.deposit(0, items); }).contains("power of two"), "n = {n}");
    }
    assert!(h.refused(&alice(), cost, |m| { m.deposit(0, vec![b64(&[1, 2])]); }).contains("bad blinded length"));

    let mut inf = [0u8; G1_LEN];
    inf[0] = 0xc0;
    assert!(h.refused(&alice(), cost, |m| { m.deposit(0, vec![b64(&inf)]); }).contains("bad blinded point"));

    assert!(h.refused(&alice(), cost, |m| { m.deposit(9, vec![good()]); }).contains("unknown denomination"));
    assert!(h.refused(&alice(), 1, |m| { m.deposit(0, vec![good()]); }).contains("too small"));
}

#[test]
fn non_subgroup_blinded_point_cannot_be_issued() {
    let mut h = H::new();
    let bad = non_subgroup_g1();
    let cost = h.cost(0, 1);
    let U64(id) = h.call(&alice(), cost, |m| m.deposit(0, vec![b64(&bad)]));
    // The honest signer refuses to lock such a record, so it ends in a refund.
    h.now += ISSUE_TIMEOUT_NS;
    h.call(&alice(), 0, |m| m.refund(U64(id)));
}

#[test]
fn refund_timing() {
    let mut h = H::new();
    let (id, _pending) = h.deposit(0, 2);
    let paid_before = h.paid_to(&alice());
    let msg = h.refused(&bob(), 0, |m| m.refund(U64(id)));
    assert!(msg.contains("deadline not reached"), "{msg}");

    h.now += ISSUE_TIMEOUT_NS;
    h.call(&bob(), 0, |m| m.refund(U64(id)));
    let returned = h.paid_to(&alice()) - paid_before;
    assert!(returned >= 2 * (UNIT + STORAGE_PER_TOKEN + ISSUE_FEE_PER_TOKEN), "the full deposit comes back");
    assert_eq!(h.counters(0).refunded, 2);

    let msg = h.refused(&bob(), 0, |m| m.refund(U64(id)));
    assert!(msg.contains("unknown deposit"), "refund twice: {msg}");
}

#[test]
fn refund_after_issue_is_refused() {
    let mut h = H::new();
    let (id, pending) = h.deposit(0, 1);
    let sigs: Vec<_> = h.sign(0, &pending).iter().map(|s| b64(s)).collect();
    h.lock_and_issue(id, sigs);
    h.now += LOCK_TIMEOUT_NS;
    let msg = h.refused(&alice(), 0, |m| m.refund(U64(id)));
    assert!(msg.contains("unknown deposit"), "{msg}");
}

#[test]
fn circulation_cap() {
    let mut h = H::with_limits(2, 100);
    h.deposit(0, 2);
    let dst = h.dst.clone();
    let b = b64(&PendingToken::new(&mut OsRng, 0, &dst).unwrap().blinded);
    let cost = h.cost(0, 1);
    let msg = h.refused(&alice(), cost, |m| { m.deposit(0, vec![b]); });
    assert!(msg.contains("circulation cap"), "{msg}");
}

#[test]
fn hourly_bucket_exhausted_then_refilled() {
    let mut h = H::with_limits(100, 2);
    let tokens = h.mint_tokens(0, 4);
    h.call(&bob(), 0, |m| rd(m, &tokens[0].0));
    h.call(&bob(), 0, |m| rd(m, &tokens[1].0));
    let msg = h.refused(&bob(), 0, |m| rd(m, &tokens[2].0));
    assert!(msg.contains("hourly redemption limit"), "{msg}");

    let items = vec![claim(&tokens[2].0, &tokens[2].1)];
    assert_eq!(h.call(&relay(), 0, |m| m.relay_claim(items)), vec![false], "the relay is limited too");

    h.now += HOUR_NS;
    h.call(&bob(), 0, |m| rd(m, &tokens[2].0));
    assert_eq!(h.counters(0).redeemed, 3);
}

#[test]
fn halt_stops_new_money_but_not_exits() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(1);
    let (t2, _) = h.mint_one(1);
    let (id, pending) = h.deposit(0, 1);
    let sigs: Vec<_> = h.sign(0, &pending).iter().map(|s| b64(s)).collect();

    let msg = h.refused(&bob(), 0, |m| m.halt());
    assert!(msg.contains("only the guardian"), "{msg}");
    h.call(&guardian(), 0, |m| m.halt());

    assert!(h.refused(&signer(), 0, |m| m.lock(U64(id))).contains("halted"));
    let args = sigs.clone();
    assert!(h.refused(&signer(), 0, |m| m.issue(U64(id), args)).contains("not locked"));
    let dst = h.dst.clone();
    let b = b64(&PendingToken::new(&mut OsRng, 0, &dst).unwrap().blinded);
    assert!(h.refused(&alice(), NEAR, |m| { m.deposit(0, vec![b]); }).contains("halted"));

    h.call(&bob(), 0, |m| rd(m, &t2));
    let value = UNIT << 1;
    let a = spend_args(&t, &owner, &bob(), value - 20 * MILLI, 20 * MILLI, &[]);
    h.call(&relay(), 0, |m| do_spend(m, a));
    h.now += ISSUE_TIMEOUT_NS;
    h.call(&bob(), 0, |m| m.refund(U64(id)));
}

#[test]
fn relay_access() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(0);
    let items = vec![claim(&t, &owner)];
    assert!(h.refused(&bob(), 0, |m| { m.relay_claim(items); }).contains("only the relay"));

    let too_many = vec![claim(&t, &owner); MAX_CLAIM + 1];
    assert!(h.refused(&relay(), 0, |m| { m.relay_claim(too_many); }).contains("too many"));
}

#[test]
fn claim_signed_for_another_relay_is_skipped() {
    let mut h = H::new();
    let (t, owner) = h.mint_one(0);
    let d = claim_digest(contract().as_str(), "other-relay.test", &t.nullifier());
    let items = vec![ClaimInput { token: token_input(&t), owner_sig: b64(&sign_digest(&owner, &d)) }];
    assert_eq!(h.call(&relay(), 0, |m| m.relay_claim(items)), vec![false]);
}

// ---------- constructor ----------

fn try_new(denoms: Vec<DenomInit>) -> String {
    context(&alice(), 0, 50 * NEAR, 0, 1);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(|| {
        Mint::new(denoms, signer(), relay(), guardian(), NETWORK.into());
    }));
    std::panic::set_hook(hook);
    panic_text(r.expect_err("constructor should refuse"))
}

#[test]
fn constructor_refuses_bad_keys() {
    let pk = keygen(&mut OsRng).public_key();
    let init = |pk: &[u8]| DenomInit {
        value: U128(UNIT),
        pk_g2: b64(pk),
        circulation_cap: 10,
        hourly_redeem_cap: 10,
    };
    assert!(try_new(vec![]).contains("denomination count"));
    assert!(try_new(vec![init(&pk), init(&pk)]).contains("duplicate"));
    assert!(try_new(vec![init(&pk[..50])]).contains("key length"));
    let mut inf = [0u8; G2_LEN];
    inf[0] = 0xc0;
    assert!(try_new(vec![init(&inf)]).contains("flags"));
    assert!(try_new(vec![init(&non_subgroup_g2())]).contains("subgroup"));
    let mut small = init(&pk);
    small.value = U128(REDEEM_FEE);
    assert!(try_new(vec![small]).contains("too small"));
}

// ---------- random walk ----------

#[test]
fn random_operations_keep_the_invariant() {
    let mut h = H::with_limits(10_000, 10_000);
    let mut live: Vec<(Token, SigningKey)> = Vec::new();
    let mut open: Vec<u64> = Vec::new();
    let mut rng = OsRng;
    for _ in 0..150 {
        match rng.gen_range(0..9) {
            0 | 1 => {
                let denom = rng.gen_range(0..4u8);
                let n = 1usize << rng.gen_range(0..3);
                live.extend(h.mint_tokens(denom, n));
            }
            2 => {
                let (id, _) = h.deposit(rng.gen_range(0..4u8), 1);
                open.push(id);
            }
            3 if !open.is_empty() => {
                h.now += ISSUE_TIMEOUT_NS;
                let id = open.swap_remove(rng.gen_range(0..open.len()));
                h.call(&bob(), 0, |m| m.refund(U64(id)));
            }
            4 if !live.is_empty() => {
                let (t, _) = live.swap_remove(rng.gen_range(0..live.len()));
                h.call(&bob(), 0, |m| rd(m, &t));
            }
            5 if !live.is_empty() => {
                let (t, owner) = live.swap_remove(rng.gen_range(0..live.len()));
                let value = UNIT << t.denom_id;
                let fee = 20 * MILLI;
                let a = spend_args(&t, &owner, &bob(), value - fee, fee, &[]);
                h.call(&relay(), 0, |m| do_spend(m, a));
            }
            6 if !live.is_empty() => {
                let (t, owner) = live.swap_remove(rng.gen_range(0..live.len()));
                let items = vec![claim(&t, &owner)];
                assert_eq!(h.call(&relay(), 0, |m| m.relay_claim(items)), vec![true]);
            }
            7 if live.iter().any(|(t, _)| t.denom_id > 0) => {
                let i = live.iter().position(|(t, _)| t.denom_id > 0).unwrap();
                let (t, owner) = live.swap_remove(i);
                let dst = h.dst.clone();
                let c = PendingToken::new(&mut OsRng, 0, &dst).unwrap();
                let change = [ChangeOut { denom_id: 0, blinded: c.blinded }];
                let fee = 50 * MILLI;
                let amount = (UNIT << t.denom_id) - UNIT - fee;
                let a = spend_args(&t, &owner, &bob(), amount, fee, &change);
                h.call(&relay(), 0, |m| do_spend(m, a));
                context(&alice(), 0, h.balance, h.storage, h.now);
                let id = h.mint.pending_deposits(U64(0), 64).last().unwrap().id.0;
                let sig = sign_blinded(&h.sks[0], &c.blinded).unwrap();
                h.lock_and_issue_with_one(id, &sig);
                let pk0 = h.pks[0];
                let (ct, k) = c.finish(&sig, &pk0).unwrap();
                OWNERS.with(|o| o.borrow_mut().insert(ct.pk, k.clone()));
                live.push((ct, k));
            }
            8 if !live.is_empty() => {
                // A refused call must not change the margin.
                let i = rng.gen_range(0..live.len());
                let mut forged = live[i].0.clone();
                forged.nonce[0] ^= 1;
                let msg = h.refused(&bob(), 0, |m| rd(m, &forged));
                assert!(msg.contains("invalid token"), "{msg}");
            }
            _ => h.call(&signer(), 0, |m| m.claim_signer_fees()),
        }
    }
    for (t, _) in live {
        h.call(&bob(), 0, |m| rd(m, &t));
    }
    h.call(&signer(), 0, |m| m.claim_signer_fees());
}
