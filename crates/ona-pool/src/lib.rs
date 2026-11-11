//! `ona-pool`: the contract that holds the funds the agent places. Draft, not audited, testnet only.
//! See `../SPEC.md`.
//!
//! The account has no access key once created. Nothing can leave it except:
//! - a placement into a vault on the guardian's list, through the fixed methods of that vault's adapter;
//! - an exit paid against a valid note, only to an account that called `deposit` and filed nothing else, within
//!   that account's limit;
//! - a refund to a depositor of its own deposits never turned into cash notes;
//! - the agent's fee, which is zero unless the guardian sets it;
//! - the storage fee of an exit request, back to the account that paid it.
//!
//! Money inside the pool lives in two kinds of places. The **cash** compartment backs blind cash notes of
//! fixed value, with no vault: deposits become cash, cash enters a vault as share notes, shares leave a vault
//! as cash, and exits pay cash notes. Each **vault** backs its share notes. Exits of cash notes name the paid
//! account and a cash tier, never a vault.
//!
//! The agent is an account set by the guardian. Checking that its key lives in an attested enclave is done
//! outside this contract, and is not built yet.

mod crypto;

use near_sdk::collections::{LookupMap, LookupSet};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise};

use crypto::{bls_valid, checked_key, owner_signed, sha256, G1_LEN};
pub use crypto::WEAK_KEYS;

pub const MAX_VAULTS: u32 = 32;
pub const MAX_TIERS: usize = 8;
/// Most notes one issue, entry or leave creates.
pub const MAX_OUTPUTS: u64 = 64;
pub const HOUR_NS: u64 = 3_600_000_000_000;
pub const DAY_NS: u64 = 24 * HOUR_NS;
pub const YEAR_NS: u64 = 365 * DAY_NS;
/// Default delay after which anyone holding notes can get paid without the agent.
pub const DEFAULT_ESCAPE_DELAY_NS: u64 = 7 * DAY_NS;
/// Default and shortest wait between a guardian announcement and its effect: at least as long as a staking
/// pool takes to return unstaked funds (not verified), so holders can leave before it.
pub const DEFAULT_ADMIN_DELAY_NS: u64 = 7 * DAY_NS;
pub const MIN_ADMIN_DELAY_NS: u64 = 7 * DAY_NS;
pub const MIN_ESCAPE_DELAY_NS: u64 = 60_000_000_000;
pub const MAX_ESCAPE_DELAY_NS: u64 = 30 * DAY_NS;
pub const MAX_REQUESTS_PER_ACCOUNT: usize = 4;
pub const MAX_REQUESTS: usize = 64;
/// Longest an exit request can wait: its owner's signature must expire within this time of filing.
pub const MAX_REQUEST_LIFE_NS: u64 = 30 * DAY_NS;
/// A note whose request was withdrawn this many times cannot be requested again.
pub const MAX_CANCELS: u8 = 3;
/// At most one successful `unstake` per vault in this time. A design margin, not a measured lock length.
pub const UNSTAKE_INTERVAL_NS: u64 = 3 * DAY_NS;
/// A share price is used for an entry, a leave or a share-note exit only if the vault was read this
/// recently, or holds nothing at its target.
pub const SYNC_FRESH_NS: u64 = HOUR_NS;
/// Price of one share in yoctoNEAR in an empty vault. 10^6 shares make one NEAR.
pub const INITIAL_PRICE: u128 = 1_000_000_000_000_000_000;
/// A third party may `withdraw` from an open vault at most once in this time.
pub const THIRD_PARTY_INTERVAL_NS: u64 = HOUR_NS;
/// Entries stop below this share price.
pub const PRICE_FLOOR: u128 = INITIAL_PRICE / 1_000;
/// Highest fee the guardian can set, in basis points of the gains. A design choice.
pub const MAX_FEE_BPS: u16 = 2_000;
/// Default and highest yearly growth an account's exit limit allows, in basis points. Design choices.
pub const DEFAULT_MAX_RATE_BPS: u16 = 2_000;
pub const MAX_RATE_BPS: u16 = 10_000;
/// Kept from each exit to pay for the storage of its nullifier and its owner key.
pub const EXIT_STORAGE_FEE: u128 = 2_000_000_000_000_000_000_000;
/// Kept from the note spent by an entry or a leave, for the storage of its nullifier and its owner key.
pub const NOTE_STORAGE_FEE: u128 = 2_000_000_000_000_000_000_000;
pub const MIN_DEPOSIT: u128 = 100_000_000_000_000_000_000_000;
/// Upper bound on the bytes one exit request adds, with a 64-character account, including the note's
/// permanent mark. An estimate, not a measure: the request fee is at least this times the chain's storage price.
pub const REQUEST_BYTES: u128 = 336;
/// Bytes of the mark a requested note keeps for good (it can never enter or leave a vault afterwards), kept
/// from the request fee when the request leaves the list. An estimate.
pub const MARK_BYTES: u128 = 80;
/// An operation on a vault whose callback never came back stops blocking the vault after this.
pub const BUSY_TIMEOUT_NS: u64 = HOUR_NS;
/// Gas given to each call into a vault, and to our own callback. Not measured on a real pool.
const VAULT_GAS: Gas = Gas::from_tgas(50);
const CALLBACK_GAS: Gas = Gas::from_tgas(20);
/// A callback that reads a balance, then calls the vault and waits for that call's own callback.
const READ_CALLBACK_GAS: Gas = Gas::from_tgas(80);

/// The kinds of protocol a vault can be. Only `Staking` has an adapter.
///
/// `Lending` is reserved: no lending interface has been checked against its source yet, so a lending vault
/// cannot be added.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Adapter {
    /// The standard NEAR staking pool: `deposit_and_stake`, `unstake`, `withdraw`,
    /// `get_account_total_balance` (names from `near/core-contracts`, not run against one).
    Staking,
    Lending,
}

impl Adapter {
    fn parse(kind: &str) -> Self {
        match kind {
            "staking" => Self::Staking,
            "lending" => Self::Lending,
            _ => env::panic_str("unknown adapter"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Staking => "staking",
            Self::Lending => "lending",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Staking => 0,
            Self::Lending => 1,
        }
    }

    fn from_code(code: u8) -> Self {
        if code == 0 {
            Self::Staking
        } else {
            Self::Lending
        }
    }

    fn require_built(self) {
        require!(self == Self::Staking, "lending adapter not implemented");
    }
}

#[near(serializers = [json])]
#[derive(Clone)]
pub struct TierInit {
    /// Shares carried by one note of this tier.
    pub shares: U128,
    /// Compressed G2 public key, 96 bytes, used for this tier of this vault only.
    pub pk_g2: Base64VecU8,
}

#[near(serializers = [json])]
#[derive(Clone)]
pub struct CashTierInit {
    /// What one cash note of this tier is worth, in yoctoNEAR.
    pub value: U128,
    /// Compressed G2 public key, 96 bytes, used for this cash tier only.
    pub pk_g2: Base64VecU8,
}

/// `count` new notes of `tier`, asked for by a cash issue, an entry or a leave.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct NoteOut {
    pub tier: u8,
    pub count: u64,
}

#[near(serializers = [json])]
#[derive(Clone)]
pub struct NoteInput {
    pub tier: u8,
    pub pk: Base64VecU8,
    pub nonce: Base64VecU8,
    pub sig: Base64VecU8,
}

#[near(serializers = [borsh])]
pub struct Tier {
    shares: u128,
    pk_raw: Vec<u8>,
    issued: u64,
    paid: u64,
}

#[near(serializers = [borsh])]
pub struct CashTier {
    value: u128,
    pk_raw: Vec<u8>,
    issued: u64,
    paid: u64,
}

#[near(serializers = [borsh])]
#[derive(Default)]
pub struct Window {
    hour: u64,
    used: u128,
}

#[near(serializers = [borsh])]
pub struct Request {
    nf: [u8; 32],
    /// When this request was filed. A withdrawn request does not keep its date.
    at: u64,
    to: AccountId,
    tier: u8,
    /// The note's owner key, marked as used when the note is paid.
    pk: [u8; 32],
    min_amount: u128,
    expires_at: u64,
    /// Storage fee, given back to `payer` (the account that filed the request, which is `to`) when the request
    /// leaves the list, less the note's permanent mark.
    fee: u128,
    payer: AccountId,
}

#[near(serializers = [borsh])]
pub struct Cash {
    dst: Vec<u8>,
    tiers: Vec<CashTier>,
    /// NEAR held for cash notes.
    liquid: u128,
    hourly_cap: u128,
    /// One window for every exit, normal or through the escape, so the rate never doubles.
    exit_window: Window,
    requests: Vec<Request>,
    full_since: u64,
}

#[near(serializers = [borsh])]
pub struct Vault {
    adapter: u8,
    target: AccountId,
    /// SHA-256 of the code the guardian checked at the target. Recorded, not verified on chain.
    code_hash: [u8; 32],
    dst: Vec<u8>,
    tiers: Vec<Tier>,
    /// Held by this contract for the vault: not placed yet, or withdrawn.
    liquid: u128,
    /// Held by the target for this contract, as last read from the target.
    placed: u128,
    /// Asked back from the target, not yet confirmed by its callback. Shown only.
    withdrawing: u128,
    fee_owed: u128,
    total_shares: u128,
    /// Left in the vault when its last shares went: owned by nobody, not counted in the price.
    orphan: u128,
    /// Highest share price seen at a sync. The fee is charged only above it.
    peak: u128,
    max_assets: u128,
    /// Applies separately to placements, and to leaves and exits (normal or through the escape) together.
    hourly_cap: u128,
    place_window: Window,
    exit_window: Window,
    /// Last `withdraw` by someone other than the agent.
    last_other_withdraw: u64,
    /// When the guardian's announcement takes effect: no entry or placement before.
    active_at: u64,
    /// Last time the target's balance was read.
    synced_at: u64,
    /// Exits of share notes asked for by their owner, the fallback when the agent does not serve them.
    requests: Vec<Request>,
    frozen: bool,
    busy_since: u64,
    busy_op: u64,
    /// Last successful `unstake`, which may restart the target's lock (not verified).
    last_unstake: u64,
    /// Last successful `unstake` whose amount the contract fixed. Kept apart, so the agent's own calls cannot
    /// hold it back.
    last_forced_unstake: u64,
    full_since: u64,
}

#[near(serializers = [borsh])]
#[derive(Default)]
pub struct Holder {
    deposited: u128,
    /// Paid back by `refund_deposit`.
    refunded: u128,
    /// Turned into cash notes by `issue_cash`.
    issued: u128,
    /// Paid by exits.
    received: u128,
    /// Growth earned so far by the account's cash still in the pool (issued − received).
    accrued: u128,
    /// When `accrued` was last brought up to date.
    accrued_at: u64,
    /// Zero, or when the account asked for a refund.
    refund_requested_at: u64,
    /// Exits and refunds whose transfer came back, claimable by the holder.
    owed: u128,
}

#[near(serializers = [json])]
pub struct TierView {
    pub shares: U128,
    /// The tier's G2 public key, uncompressed (192 bytes, the form NEAR's BLS host functions use).
    pub pk_raw: Base64VecU8,
    pub issued: u64,
    pub paid: u64,
}

#[near(serializers = [json])]
pub struct CashTierView {
    pub value: U128,
    pub pk_raw: Base64VecU8,
    pub issued: u64,
    pub paid: u64,
}

#[near(serializers = [json])]
pub struct VaultView {
    pub adapter: String,
    pub target: AccountId,
    pub code_hash: Base64VecU8,
    pub tiers: Vec<TierView>,
    pub liquid: U128,
    pub placed: U128,
    pub withdrawing: U128,
    pub fee_owed: U128,
    pub total_shares: U128,
    /// Left in the vault when its last shares went, owned by nobody and not counted in the price.
    pub orphan: U128,
    pub share_price: U128,
    pub synced_at: u64,
    pub max_assets: U128,
    pub hourly_cap: U128,
    pub frozen: bool,
    pub busy: bool,
    pub busy_op: u64,
    pub requests: u32,
    pub open: bool,
}

#[near(serializers = [json])]
pub struct CashView {
    pub tiers: Vec<CashTierView>,
    pub liquid: U128,
    /// Value of the cash notes issued and not paid. Never more than `liquid`.
    pub outstanding: U128,
    pub hourly_cap: U128,
    pub requests: u32,
    pub open: bool,
}

#[near(serializers = [json])]
pub struct HolderView {
    pub deposited: U128,
    pub refunded: U128,
    pub issued: U128,
    pub received: U128,
    pub owed: U128,
    pub exit_limit: U128,
    pub refundable: U128,
}

#[near(serializers = [json])]
pub struct ConfigView {
    pub guardian: AccountId,
    pub agent: AccountId,
    pub pending_agent: Option<AccountId>,
    pub admin_pending_until: u64,
    pub admin_delay_ns: u64,
    pub network: String,
    pub escape_delay_ns: u64,
    pub last_agent_call: u64,
    pub escape_open: bool,
    pub fee_bps: u16,
    pub pending_fee_bps: Option<u16>,
    pub max_rate_bps: u16,
    pub vault_count: u32,
}

#[near(serializers = [json])]
pub struct ReserveStatus {
    pub balance: U128,
    pub storage_cost: U128,
    /// The vaults' liquid funds.
    pub liquid: U128,
    pub cash: U128,
    pub owed: U128,
    /// Deposited and not yet turned into cash notes.
    pub unassigned: U128,
    /// Storage fees of waiting requests, owed back to their accounts.
    pub held_fees: U128,
    pub solvent: bool,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Pool {
    guardian: AccountId,
    agent: AccountId,
    pending_agent: Option<(AccountId, u64)>,
    /// The escape stays open to everyone until every guardian announcement has taken effect.
    admin_pending_until: u64,
    admin_delay_ns: u64,
    network: String,
    escape_delay_ns: u64,
    last_agent_call: u64,
    fee_bps: u16,
    /// A fee announced by the guardian, and when it takes effect.
    pending_fee: Option<(u16, u64)>,
    max_rate_bps: u16,
    vault_count: u32,
    total_liquid: u128,
    total_owed: u128,
    /// Deposited and not yet turned into cash notes. Counted, never read from the balance.
    unassigned: u128,
    held_fees: u128,
    cash: Cash,
    vaults: LookupMap<u32, Vault>,
    keys: LookupSet<[u8; 32]>,
    targets: LookupSet<AccountId>,
    holders: LookupMap<AccountId, Holder>,
    nullifiers: LookupSet<[u8; 32]>,
    /// Every note ever named in an exit request, with how many times its request was withdrawn. Such a note
    /// can only leave the pool by an exit, never enter or leave a vault.
    requested: LookupMap<[u8; 32], u8>,
    /// Owner keys of every note spent: a key serves one note only.
    owner_keys: LookupSet<[u8; 32]>,
    /// Live notes a tier must have before the agent spends one of them in `enter` or pays one with `pay_exit`.
    min_live_notes: u64,
}

fn now() -> u64 {
    env::block_timestamp()
}

fn fixed<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

fn add(a: u128, b: u128) -> u128 {
    a.checked_add(b).unwrap_or_else(|| env::panic_str("amount overflow"))
}

fn mul(a: u128, b: u128) -> u128 {
    a.checked_mul(b).unwrap_or_else(|| env::panic_str("amount overflow"))
}

fn event(name: &str, data: &str) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"ona-pool\",\"version\":\"2.0.0\",\"event\":\"{name}\",\"data\":{data}}}"
    ));
}

/// Domain tag for hashing a share note of one vault. Each vault has its own keys as well, because a
/// blind signer cannot see which tag a point was hashed with.
pub fn note_dst(network: &str, contract: &str, vault_id: u32) -> String {
    format!("ONA-POOL-V1:{network}:{contract}:{vault_id}:BLS12381G1_XMD:SHA-256_SSWU_RO_")
}

/// Domain tag for hashing a cash note.
pub fn cash_dst(network: &str, contract: &str) -> String {
    format!("ONA-POOL-CASH-V1:{network}:{contract}:BLS12381G1_XMD:SHA-256_SSWU_RO_")
}

/// `SHA-256("ONA-POOL-NF-V1" || vault_id (u32 LE) || tier || pk || nonce)`.
pub fn note_nullifier(vault_id: u32, tier: u8, pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut d = Vec::with_capacity(83);
    d.extend_from_slice(b"ONA-POOL-NF-V1");
    d.extend_from_slice(&vault_id.to_le_bytes());
    d.push(tier);
    d.extend_from_slice(pk);
    d.extend_from_slice(nonce);
    sha256(&d)
}

/// `SHA-256("ONA-POOL-CASH-NF-V1" || tier || pk || nonce)`.
pub fn cash_nullifier(tier: u8, pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut d = Vec::with_capacity(84);
    d.extend_from_slice(b"ONA-POOL-CASH-NF-V1");
    d.push(tier);
    d.extend_from_slice(pk);
    d.extend_from_slice(nonce);
    sha256(&d)
}

fn outputs_bytes(d: &mut Vec<u8>, outputs: &[NoteOut]) {
    d.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
    for o in outputs {
        d.push(o.tier);
        d.extend_from_slice(&o.count.to_le_bytes());
    }
}

/// What a cash note's owner signs to be paid: the pool, the note, the paid account and a deadline.
/// `SHA-256("ONA-POOL-CASH-EXIT-V1" || H(contract) || nf || H(to) || expires_at (u64 LE))`.
pub fn cash_exit_digest(contract: &AccountId, nf: &[u8; 32], to: &AccountId, expires_at: u64) -> [u8; 32] {
    let mut d = Vec::with_capacity(125);
    d.extend_from_slice(b"ONA-POOL-CASH-EXIT-V1");
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(nf);
    d.extend_from_slice(&sha256(to.as_bytes()));
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// What a share note's owner signs to be paid directly from its vault (the fallback, which shows the vault).
/// `SHA-256("ONA-POOL-EXIT-V2" || H(contract) || vault_id (u32 LE) || nf || H(to) || min_amount (u128 LE) || expires_at (u64 LE))`.
pub fn share_exit_digest(
    contract: &AccountId,
    vault_id: u32,
    nf: &[u8; 32],
    to: &AccountId,
    min_amount: u128,
    expires_at: u64,
) -> [u8; 32] {
    let mut d = Vec::with_capacity(140);
    d.extend_from_slice(b"ONA-POOL-EXIT-V2");
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(&vault_id.to_le_bytes());
    d.extend_from_slice(nf);
    d.extend_from_slice(&sha256(to.as_bytes()));
    d.extend_from_slice(&min_amount.to_le_bytes());
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// What a cash note's owner signs to turn it into share notes of a vault.
/// `SHA-256("ONA-POOL-ENTER-V1" || H(contract) || nf || vault_id (u32 LE) || n (u32 LE) || (tier || count (u64 LE))*n || expires_at (u64 LE))`.
pub fn enter_digest(contract: &AccountId, nf: &[u8; 32], vault_id: u32, outputs: &[NoteOut], expires_at: u64) -> [u8; 32] {
    let mut d = Vec::with_capacity(97 + outputs.len() * 9);
    d.extend_from_slice(b"ONA-POOL-ENTER-V1");
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(nf);
    d.extend_from_slice(&vault_id.to_le_bytes());
    outputs_bytes(&mut d, outputs);
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// What a share note's owner signs to turn it into cash notes.
/// `SHA-256("ONA-POOL-LEAVE-V1" || H(contract) || vault_id (u32 LE) || nf || n (u32 LE) || (tier || count (u64 LE))*n || expires_at (u64 LE))`.
pub fn leave_digest(contract: &AccountId, vault_id: u32, nf: &[u8; 32], outputs: &[NoteOut], expires_at: u64) -> [u8; 32] {
    let mut d = Vec::with_capacity(97 + outputs.len() * 9);
    d.extend_from_slice(b"ONA-POOL-LEAVE-V1");
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(&vault_id.to_le_bytes());
    d.extend_from_slice(nf);
    outputs_bytes(&mut d, outputs);
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// Total assets of a vault, less its fee and what no share owns: what its share price divides.
fn assets(v: &Vault) -> u128 {
    v.liquid.saturating_add(v.placed).saturating_sub(v.fee_owed).saturating_sub(v.orphan)
}

/// Price rounded down: what a note is worth when it leaves. The initial price in a vault with no share.
fn price(v: &Vault) -> u128 {
    if v.total_shares == 0 {
        INITIAL_PRICE
    } else {
        assets(v) / v.total_shares
    }
}

/// Price rounded up: what a share costs when it enters.
fn price_up(v: &Vault) -> u128 {
    if v.total_shares == 0 {
        return INITIAL_PRICE;
    }
    let a = assets(v);
    a / v.total_shares + u128::from(a % v.total_shares != 0)
}

/// When the last shares are gone, what is left in the vault (unread rewards, rounding) belongs to nobody: it
/// is set aside so the next entrant does not take it.
fn orphan_rest(v: &mut Vault) {
    if v.total_shares == 0 {
        v.orphan = v.liquid.saturating_add(v.placed).saturating_sub(v.fee_owed);
    }
}

/// The price can be used: read from the target within `SYNC_FRESH_NS`, or nothing is placed.
fn fresh(v: &Vault) -> bool {
    v.placed == 0 || now() <= v.synced_at.saturating_add(SYNC_FRESH_NS)
}

/// Reads a `U128` result, which NEAR encodes as a JSON string.
fn parse_u128(bytes: &[u8]) -> Option<u128> {
    let s = core::str::from_utf8(bytes).ok()?.trim();
    s.strip_prefix('"')?.strip_suffix('"')?.parse().ok()
}

fn delay_ns(secs: Option<u64>, min: u64, refusal: &str) -> u64 {
    let ns = secs.map(|s| s.checked_mul(1_000_000_000).unwrap_or(u64::MAX)).unwrap_or(DEFAULT_ESCAPE_DELAY_NS);
    require!((min..=MAX_ESCAPE_DELAY_NS).contains(&ns), refusal);
    ns
}

/// `a * b / c` rounded down, and whether it was rounded, without overflow. The quotient must fit in 128 bits.
fn mul_div_rem(a: u128, b: u128, c: u128) -> (u128, bool) {
    if c == 0 {
        return (0, false);
    }
    if let Some(p) = a.checked_mul(b) {
        return (p / c, p % c != 0);
    }
    // 256-bit product, then long division.
    let (a1, a0) = (a >> 64, a & u128::from(u64::MAX));
    let (b1, b0) = (b >> 64, b & u128::from(u64::MAX));
    let (mid, carry_mid) = (a0 * b1).overflowing_add(a1 * b0);
    let (lo, carry_lo) = (a0 * b0).overflowing_add(mid << 64);
    let hi = a1 * b1 + (mid >> 64) + (u128::from(carry_mid) << 64) + u128::from(carry_lo);
    let (mut rem, mut q) = (0u128, 0u128);
    for i in (0..256).rev() {
        let bit = if i >= 128 { hi >> (i - 128) & 1 } else { lo >> i & 1 };
        let top = rem >> 127;
        rem = rem << 1 | bit;
        q <<= 1;
        if top == 1 || rem >= c {
            rem = rem.wrapping_sub(c);
            q |= 1;
        }
    }
    (q, rem != 0)
}

fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    mul_div_rem(a, b, c).0
}

fn mul_div_up(a: u128, b: u128, c: u128) -> u128 {
    let (q, rounded) = mul_div_rem(a, b, c);
    q.saturating_add(u128::from(rounded))
}

fn amount_args(amount: u128) -> Vec<u8> {
    format!("{{\"amount\":\"{amount}\"}}").into_bytes()
}

/// A note's parts, checked for length.
fn parse_note(note: &NoteInput) -> ([u8; 32], [u8; 32], [u8; G1_LEN]) {
    let bad = "bad note encoding";
    (
        fixed(&note.pk.0).unwrap_or_else(|| env::panic_str(bad)),
        fixed(&note.nonce.0).unwrap_or_else(|| env::panic_str(bad)),
        fixed(&note.sig.0).unwrap_or_else(|| env::panic_str(bad)),
    )
}

fn message(tier: u8, pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 65] {
    let mut m = [0u8; 65];
    m[0] = tier;
    m[1..33].copy_from_slice(pk);
    m[33..].copy_from_slice(nonce);
    m
}

/// Counts in an empty hour any single amount, so one note larger than the cap can still pass; otherwise the
/// hour's total must stay under the cap. Hours are calendar hours.
fn use_window(w: &mut Window, cap: u128, amount: u128) {
    let hour = now() / HOUR_NS;
    if hour != w.hour {
        w.hour = hour;
        w.used = 0;
    }
    require!(w.used == 0 || w.used.saturating_add(amount) <= cap, "hourly limit reached");
    w.used = w.used.saturating_add(amount);
}

/// Starts the clock when a request list fills up, and stops it only once the list is down to half.
fn track_full(requests: &[Request], full_since: &mut u64) {
    if requests.len() >= MAX_REQUESTS {
        if *full_since == 0 {
            *full_since = now().max(1);
        }
    } else if requests.len() <= MAX_REQUESTS / 2 {
        *full_since = 0;
    }
}

/// Marks the vault busy with a new operation and returns its number.
fn start(v: &mut Vault) -> u64 {
    require!(
        v.busy_since == 0 || now() >= v.busy_since.saturating_add(BUSY_TIMEOUT_NS),
        "an operation on this vault is still running"
    );
    v.busy_since = now().max(1);
    v.busy_op += 1;
    v.busy_op
}

/// Frees the vault, only if `op` is the operation it is busy with.
fn finish(v: &mut Vault, op: u64) {
    if v.busy_op == op {
        v.busy_since = 0;
    }
}

/// Checks the list of new notes against the tiers' count. Returns the sum of `count * per_tier(tier)`.
fn sum_outputs(outputs: &[NoteOut], tiers: usize, per_tier: impl Fn(usize) -> u128) -> u128 {
    require!(!outputs.is_empty() && outputs.len() <= MAX_TIERS, "bad output count");
    let mut count = 0u64;
    let mut total = 0u128;
    for o in outputs {
        require!(usize::from(o.tier) < tiers, "unknown tier");
        require!(o.count > 0, "count must be positive");
        count = count.saturating_add(o.count);
        total = add(total, mul(per_tier(usize::from(o.tier)), u128::from(o.count)));
    }
    require!(count <= MAX_OUTPUTS, "at most 64 new notes at once");
    total
}

#[near]
impl Pool {
    /// `escape_delay_secs` and `admin_delay_secs` default to 7 days each (the admin delay at least 7 days), at
    /// most 30. `cash_tiers` sets the cash notes, each worth more than the exit fees. `cash_hourly_cap` is
    /// the most cash exits may pay per hour, at least two of the largest cash notes. `max_rate_bps` is the
    /// yearly growth of exit limits, 20 % by default, at most 100 %. `min_live_notes` (at least 1) is how many
    /// live notes a tier must have before the agent spends one in `enter` or pays one with `pay_exit`.
    #[init]
    pub fn new(
        guardian: AccountId,
        agent: AccountId,
        network: String,
        escape_delay_secs: Option<u64>,
        admin_delay_secs: Option<u64>,
        cash_tiers: Vec<CashTierInit>,
        cash_hourly_cap: U128,
        max_rate_bps: Option<u16>,
        min_live_notes: u64,
    ) -> Self {
        require!(min_live_notes >= 1, "min_live_notes must be at least 1");
        let escape_delay_ns =
            delay_ns(escape_delay_secs, MIN_ESCAPE_DELAY_NS, "escape delay must be between one minute and 30 days");
        let admin_delay_ns =
            delay_ns(admin_delay_secs, MIN_ADMIN_DELAY_NS, "admin delay must be between 7 and 30 days");
        require!(guardian != agent, "guardian and agent must differ");
        let max_rate_bps = max_rate_bps.unwrap_or(DEFAULT_MAX_RATE_BPS);
        require!(max_rate_bps <= MAX_RATE_BPS, "rate too high");
        require!(!cash_tiers.is_empty() && cash_tiers.len() <= MAX_TIERS, "bad tier count");
        let dst = cash_dst(&network, env::current_account_id().as_str());
        require!(dst.len() <= 255, "DST too long");
        let mut keys = LookupSet::new(b"k".to_vec());
        let mut tiers = Vec::with_capacity(cash_tiers.len());
        for t in &cash_tiers {
            require!(t.value.0 > EXIT_STORAGE_FEE + NOTE_STORAGE_FEE, "a cash note must be worth more than its fees");
            let pk_raw = checked_key(&t.pk_g2.0);
            require!(keys.insert(&sha256(&t.pk_g2.0)), "key already used");
            tiers.push(CashTier { value: t.value.0, pk_raw, issued: 0, paid: 0 });
        }
        let largest = tiers.iter().map(|t| t.value).max().unwrap_or(0);
        require!(cash_hourly_cap.0 >= largest.saturating_mul(2), "the hourly cap must cover two of the largest notes");
        Self {
            guardian,
            agent,
            pending_agent: None,
            admin_pending_until: 0,
            admin_delay_ns,
            network,
            escape_delay_ns,
            last_agent_call: now(),
            fee_bps: 0,
            pending_fee: None,
            max_rate_bps,
            vault_count: 0,
            total_liquid: 0,
            total_owed: 0,
            unassigned: 0,
            held_fees: 0,
            cash: Cash {
                dst: dst.into_bytes(),
                tiers,
                liquid: 0,
                hourly_cap: cash_hourly_cap.0,
                exit_window: Window::default(),
                requests: Vec::new(),
                full_since: 0,
            },
            vaults: LookupMap::new(b"v".to_vec()),
            keys,
            targets: LookupSet::new(b"t".to_vec()),
            holders: LookupMap::new(b"h".to_vec()),
            nullifiers: LookupSet::new(b"n".to_vec()),
            requested: LookupMap::new(b"c".to_vec()),
            owner_keys: LookupSet::new(b"o".to_vec()),
            min_live_notes,
        }
    }

    // ---- depositors ----

    /// The only way to become an account that can receive exits: the caller and the attached amount are
    /// recorded by the contract itself. The storage the record adds is paid from the deposit.
    #[payable]
    pub fn deposit(&mut self) {
        let account = env::predecessor_account_id();
        let attached = env::attached_deposit().as_yoctonear();
        require!(attached >= MIN_DEPOSIT, "deposit too small");
        let before = env::storage_usage();
        let mut h = self.holders.get(&account).unwrap_or_default();
        self.holders.insert(&account, &h);
        let storage = u128::from(env::storage_usage().saturating_sub(before))
            .saturating_mul(env::storage_byte_cost().as_yoctonear());
        require!(attached > storage, "deposit too small");
        let credited = attached - storage;
        self.accrue(&mut h);
        h.deposited = add(h.deposited, credited);
        self.holders.insert(&account, &h);
        self.unassigned = add(self.unassigned, credited);
        self.require_solvent();
        event("deposit", "{}");
    }

    /// Asks for a refund of this account's deposits not yet turned into cash. After the escape delay,
    /// `refund_deposit` opens for this account even while the agent is active.
    pub fn request_refund(&mut self) {
        let account = env::predecessor_account_id();
        let mut h = self.holders.get(&account).unwrap_or_else(|| env::panic_str("not a depositor"));
        require!(self.refundable(&h) > 0, "nothing left to refund");
        require!(h.refund_requested_at == 0, "refund already requested");
        h.refund_requested_at = now().max(1);
        self.holders.insert(&account, &h);
        event("refund_requested", "{}");
    }

    /// While the escape is open, or once this account's refund request has waited the escape delay, a
    /// depositor takes back its own deposits that were never turned into cash notes, and nothing else.
    pub fn refund_deposit(&mut self, amount: U128) {
        let account = env::predecessor_account_id();
        let mut h = self.holders.get(&account).unwrap_or_else(|| env::panic_str("not a depositor"));
        let requested =
            h.refund_requested_at != 0 && now() >= h.refund_requested_at.saturating_add(self.escape_delay_ns);
        require!(self.escape_open() || requested, "the agent is still active");
        require!(amount.0 > 0, "amount must be positive");
        require!(amount.0 <= self.refundable(&h), "more than this account's deposits not turned into cash");
        self.accrue(&mut h);
        h.refunded = add(h.refunded, amount.0);
        if self.refundable(&h) == 0 {
            h.refund_requested_at = 0;
        }
        self.holders.insert(&account, &h);
        self.unassigned -= amount.0;
        self.pay(account, amount.0);
        self.require_solvent();
        event("refund", "{}");
    }

    // ---- guardian ----

    /// Announces a checked vault. Returns its id. It takes entries and placements only after the admin delay,
    /// and the escape is open to everyone until then. A target can serve one vault only. The hourly cap must
    /// cover two of the vault's largest notes at the initial price.
    pub fn add_vault(
        &mut self,
        kind: String,
        target: AccountId,
        code_hash: Base64VecU8,
        tiers: Vec<TierInit>,
        max_assets: U128,
        hourly_cap: U128,
    ) -> u32 {
        self.only_guardian();
        let adapter = Adapter::parse(&kind);
        adapter.require_built();
        require!(self.vault_count < MAX_VAULTS, "too many vaults");
        require!(target != env::current_account_id(), "a vault cannot be the pool");
        require!(!self.targets.contains(&target), "this target already serves a vault");
        require!(!tiers.is_empty() && tiers.len() <= MAX_TIERS, "bad tier count");
        require!(max_assets.0 > 0, "caps must be positive");
        let code_hash: [u8; 32] = fixed(&code_hash.0).unwrap_or_else(|| env::panic_str("bad code hash length"));
        let largest = tiers.iter().map(|t| t.shares.0).max().unwrap_or(0);
        require!(
            hourly_cap.0 >= largest.saturating_mul(INITIAL_PRICE).saturating_mul(2),
            "the hourly cap must cover two of the largest notes"
        );

        let id = self.vault_count;
        let mut list = Vec::with_capacity(tiers.len());
        for t in &tiers {
            require!(t.shares.0 > 0, "a tier needs shares");
            let pk_raw = checked_key(&t.pk_g2.0);
            require!(self.keys.insert(&sha256(&t.pk_g2.0)), "key already used");
            list.push(Tier { shares: t.shares.0, pk_raw, issued: 0, paid: 0 });
        }
        let dst = note_dst(&self.network, env::current_account_id().as_str(), id);
        require!(dst.len() <= 255, "DST too long");
        let active_at = self.announce();
        self.targets.insert(&target);
        self.vaults.insert(
            &id,
            &Vault {
                adapter: adapter.code(),
                target: target.clone(),
                code_hash,
                dst: dst.into_bytes(),
                tiers: list,
                liquid: 0,
                placed: 0,
                withdrawing: 0,
                fee_owed: 0,
                total_shares: 0,
                orphan: 0,
                peak: INITIAL_PRICE,
                max_assets: max_assets.0,
                hourly_cap: hourly_cap.0,
                place_window: Window::default(),
                exit_window: Window::default(),
                last_other_withdraw: 0,
                active_at,
                synced_at: 0,
                requests: Vec::new(),
                frozen: false,
                busy_since: 0,
                busy_op: 0,
                last_unstake: 0,
                last_forced_unstake: 0,
                full_since: 0,
            },
        );
        self.vault_count += 1;
        self.require_solvent();
        event("add_vault", &format!("{{\"id\":{id},\"kind\":\"{}\",\"target\":\"{target}\"}}", adapter.name()));
        id
    }

    /// Stops new entries and placements. Withdrawals, leaves and exits keep working.
    pub fn freeze_vault(&mut self, vault_id: u32) {
        self.only_guardian();
        let mut v = self.vault(vault_id);
        v.frozen = true;
        self.vaults.insert(&vault_id, &v);
        event("freeze_vault", &format!("{{\"id\":{vault_id}}}"));
    }

    /// Announces a new agent, which takes over after the admin delay. Until then the current agent keeps
    /// working, cannot place, and the escape is open to everyone.
    pub fn set_agent(&mut self, agent: AccountId) {
        self.only_guardian();
        require!(agent != self.guardian, "guardian and agent must differ");
        self.agent = self.current_agent();
        let at = self.announce();
        self.pending_agent = Some((agent, at));
        event("set_agent", &format!("{{\"effective_at\":{at}}}"));
    }

    /// Announces the agent's share of the gains above each vault's highest price, in basis points. It takes
    /// effect after the admin delay, and only for gains read by syncs that start after that.
    pub fn set_fee_bps(&mut self, fee_bps: u16) {
        self.only_guardian();
        require!(fee_bps <= MAX_FEE_BPS, "fee too high");
        self.fee_bps = self.fee_at(now());
        let at = self.announce();
        self.pending_fee = Some((fee_bps, at));
        event("set_fee", &format!("{{\"bps\":{fee_bps},\"effective_at\":{at}}}"));
    }

    // ---- agent: money in ----

    /// Turns `count` cash notes of `tier` worth of this account's deposits into cash. The agent then
    /// blind-signs the notes off chain. Names the account, as its deposit already did, and no vault.
    pub fn issue_cash(&mut self, account: AccountId, tier: u8, count: u64) {
        self.only_agent();
        require!(count > 0 && count <= MAX_OUTPUTS, "count must be between 1 and 64");
        let mut h = self.holders.get(&account).unwrap_or_else(|| env::panic_str("not a depositor"));
        require!(h.refund_requested_at == 0, "this account asked for a refund");
        let t = self.cash.tiers.get(usize::from(tier)).unwrap_or_else(|| env::panic_str("unknown tier"));
        let value = mul(t.value, u128::from(count));
        require!(value <= self.refundable(&h), "more than this account's deposits not turned into cash");
        self.accrue(&mut h);
        h.issued = add(h.issued, value);
        self.holders.insert(&account, &h);
        self.unassigned -= value;
        self.cash.liquid = add(self.cash.liquid, value);
        self.cash.tiers[usize::from(tier)].issued += count;
        self.require_solvent();
        event("issue", &format!("{{\"tier\":{tier},\"count\":{count}}}"));
    }

    /// Spends a cash note for share notes of a vault, at the vault's price rounded up, read within the hour.
    /// Signed by the note's owner for exactly these outputs and this deadline. What is left, less than one of
    /// the vault's smallest notes, stays in the cash. Refused for a note ever named in an exit request, and
    /// unless the note's cash tier has at least `min_live_notes` live notes. Names no account.
    pub fn enter(
        &mut self,
        vault_id: u32,
        note: NoteInput,
        owner_sig: Base64VecU8,
        outputs: Vec<NoteOut>,
        expires_at: u64,
    ) {
        self.only_agent();
        require!(now() <= expires_at, "the owner's signature has expired");
        require!(now() >= self.admin_pending_until, "no entry while an announcement is pending");
        let mut v = self.vault(vault_id);
        require!(!v.frozen, "vault frozen");
        require!(now() >= v.active_at, "vault not active yet");
        require!(fresh(&v), "sync this vault first");
        require!(price(&v) >= PRICE_FLOOR, "share price too low for new entries");
        let contract = env::current_account_id();
        let nf = self.check_cash_note(&note, &owner_sig, |nf| enter_digest(&contract, nf, vault_id, &outputs, expires_at));
        self.not_requested(&nf);
        let pk = self.fresh_owner_key(&note);
        let t = &self.cash.tiers[usize::from(note.tier)];
        require!(t.paid < t.issued, "more notes spent than issued");
        require!(t.issued - t.paid >= self.min_live_notes, "too few live notes in this tier: wait for more");
        let value = t.value;

        let shares = sum_outputs(&outputs, v.tiers.len(), |i| v.tiers[i].shares);
        let pu = price_up(&v);
        let cost = mul(shares, pu);
        require!(add(cost, NOTE_STORAGE_FEE) <= value, "the new notes are worth more than the note");
        let smallest = v.tiers.iter().map(|t| t.shares).min().unwrap_or(0).saturating_mul(pu);
        require!(value - NOTE_STORAGE_FEE - cost < smallest, "too much left over: ask for more notes");
        require!(add(v.liquid.saturating_add(v.placed), cost) <= v.max_assets, "vault cap reached");

        self.nullifiers.insert(&nf);
        self.owner_keys.insert(&pk);
        self.cash.tiers[usize::from(note.tier)].paid += 1;
        self.cash.liquid -= cost + NOTE_STORAGE_FEE;
        v.total_shares = add(v.total_shares, shares);
        v.liquid = add(v.liquid, cost);
        let paid = cost;
        for o in &outputs {
            v.tiers[usize::from(o.tier)].issued += o.count;
        }
        self.vaults.insert(&vault_id, &v);
        self.total_liquid = add(self.total_liquid, paid);
        self.require_solvent();
        event("enter", &format!("{{\"vault\":{vault_id}}}"));
    }

    /// Spends a share note for cash notes, at the vault's price rounded down, read within the hour. Signed by
    /// the note's owner for exactly these outputs and this deadline. The vault pays the whole note from its
    /// liquid funds at once, so cash is never backed by a promise; when the vault lacks liquid funds the
    /// leave waits until the agent brings them back. What the new cash notes do not cover, less than the
    /// smallest cash note, stays in the cash, owned by nobody. Counts in the vault's exit window. Refused for
    /// a note ever named in an exit request. Names no account.
    pub fn leave(
        &mut self,
        vault_id: u32,
        note: NoteInput,
        owner_sig: Base64VecU8,
        outputs: Vec<NoteOut>,
        expires_at: u64,
    ) {
        self.only_agent();
        require!(now() <= expires_at, "the owner's signature has expired");
        let mut v = self.vault(vault_id);
        require!(fresh(&v), "sync this vault first");
        let contract = env::current_account_id();
        let nf = self.check_share_note(&v, vault_id, &note, &owner_sig, |nf| {
            leave_digest(&contract, vault_id, nf, &outputs, expires_at)
        });
        self.not_requested(&nf);
        let pk = self.fresh_owner_key(&note);
        let t = &v.tiers[usize::from(note.tier)];
        require!(t.paid < t.issued, "more notes spent than issued");
        let note_shares = t.shares;
        let p = price(&v);
        let value = mul(note_shares, p);
        let cash = sum_outputs(&outputs, self.cash.tiers.len(), |i| self.cash.tiers[i].value);
        let claim = add(cash, NOTE_STORAGE_FEE);
        require!(claim <= value, "the new notes are worth more than the note");
        let smallest = self.cash.tiers.iter().map(|t| t.value).min().unwrap_or(0);
        require!(value - claim < smallest, "too much left over: ask for more notes");
        // The cash never holds a promise: the vault pays the whole note now, or the leave waits for liquid funds.
        require!(value <= v.liquid, "not enough liquid funds in this vault: bring funds back first");
        require!(
            v.liquid - value >= self.reserved(&v, None),
            "these funds are kept for the exit requests waiting on this vault"
        );
        let cap = v.hourly_cap;
        use_window(&mut v.exit_window, cap, value);

        // The whole note goes to the cash: what the new cash notes do not cover stays there, owned by nobody,
        // rather than going to the vault's remaining holders.
        self.nullifiers.insert(&nf);
        self.owner_keys.insert(&pk);
        v.tiers[usize::from(note.tier)].paid += 1;
        v.total_shares -= note_shares;
        v.liquid -= value;
        orphan_rest(&mut v);
        self.total_liquid -= value;
        self.cash.liquid = add(self.cash.liquid, value - NOTE_STORAGE_FEE);
        for o in &outputs {
            self.cash.tiers[usize::from(o.tier)].issued += o.count;
        }
        self.vaults.insert(&vault_id, &v);
        self.require_solvent();
        event("leave", &format!("{{\"vault\":{vault_id}}}"));
    }

    // ---- agent: the vaults ----

    /// Stakes `amount` of the vault's liquid funds with its target. Refused while an announcement is pending,
    /// and while the vault is open to others. Counts as agent activity.
    pub fn place(&mut self, vault_id: u32, amount: U128) {
        self.only_agent();
        let mut v = self.vault(vault_id);
        Adapter::from_code(v.adapter).require_built();
        require!(!v.frozen, "vault frozen");
        require!(now() >= v.active_at, "vault not active yet");
        require!(now() >= self.admin_pending_until, "no placement while an announcement is pending");
        require!(!self.vault_open(&v), "this vault is open to holders: no placement");
        require!(amount.0 > 0 && amount.0 <= v.liquid, "amount above the vault's liquid funds");
        let cap = v.hourly_cap;
        use_window(&mut v.place_window, cap, amount.0);
        let op = start(&mut v);
        self.last_agent_call = now();
        v.liquid -= amount.0;
        v.placed = add(v.placed, amount.0);
        let target = v.target.clone();
        self.vaults.insert(&vault_id, &v);
        self.total_liquid -= amount.0;
        let _ = Promise::new(target)
            .function_call("deposit_and_stake", Vec::new(), NearToken::from_yoctonear(amount.0), VAULT_GAS)
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_place(vault_id, amount, op));
        event("place", &format!("{{\"vault\":{vault_id},\"amount\":\"{}\"}}", amount.0));
    }

    /// Asks the target to unstake. The agent chooses `amount` while the vault is not open; once it is open,
    /// anyone may call, the agent included, and the amount is fixed by the contract: what waiting exits need
    /// beyond the liquid funds, or everything placed if the agent has been silent for the escape delay. At
    /// most one successful call per `UNSTAKE_INTERVAL_NS` of each kind: the agent's own calls and the calls
    /// with a fixed amount have separate intervals, so the agent cannot hold back the one the contract fixes.
    /// A failed call does not count.
    pub fn unstake(&mut self, vault_id: u32, amount: Option<U128>) {
        let mut v = self.vault(vault_id);
        Adapter::from_code(v.adapter).require_built();
        let forced = self.forced(&v);
        let amount = self.call_amount(&v, amount);
        let last = if forced { v.last_forced_unstake } else { v.last_unstake };
        require!(last == 0 || now() >= last.saturating_add(UNSTAKE_INTERVAL_NS), "unstaked too recently on this vault");
        let op = start(&mut v);
        let target = v.target.clone();
        self.vaults.insert(&vault_id, &v);
        if forced {
            // `placed` counts staked and already unstaked funds together, and the staking pool refuses to unstake
            // more than is staked (not verified): read what is unstaked and what is staked, then ask for at most the
            // staked part, and only if nothing unstaked is waiting (each `unstake` may restart its lock).
            let _ = Promise::new(target.clone())
                .function_call("get_account_unstaked_balance", self.account_args(), NearToken::from_yoctonear(0), VAULT_GAS)
                .and(Promise::new(target).function_call(
                    "get_account_staked_balance",
                    self.account_args(),
                    NearToken::from_yoctonear(0),
                    VAULT_GAS,
                ))
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(READ_CALLBACK_GAS)
                        .on_staked_read(vault_id, op, U128(amount)),
                );
        } else {
            let _ = Promise::new(target)
                .function_call("unstake", amount_args(amount), NearToken::from_yoctonear(0), VAULT_GAS)
                .then(
                    Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_unstake(vault_id, op, false),
                );
        }
        event("unstake", &format!("{{\"vault\":{vault_id},\"amount\":\"{amount}\"}}"));
    }

    /// Brings unstaked funds back into the pool, with the same rule for the amount as `unstake`.
    pub fn withdraw(&mut self, vault_id: u32, amount: Option<U128>) {
        let mut v = self.vault(vault_id);
        Adapter::from_code(v.adapter).require_built();
        let forced = self.forced(&v);
        let amount = self.call_amount(&v, amount);
        if env::predecessor_account_id() != self.current_agent() {
            require!(
                now() >= v.last_other_withdraw.saturating_add(THIRD_PARTY_INTERVAL_NS),
                "withdrawn by someone else less than an hour ago"
            );
            v.last_other_withdraw = now().max(1);
        }
        let op = start(&mut v);
        let target = v.target.clone();
        if forced {
            // The staking pool refuses to withdraw more than is already unstaked (not verified): read it first.
            self.vaults.insert(&vault_id, &v);
            let _ = Promise::new(target)
                .function_call(
                    "get_account_unstaked_balance",
                    self.account_args(),
                    NearToken::from_yoctonear(0),
                    VAULT_GAS,
                )
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(READ_CALLBACK_GAS)
                        .on_unstaked_read(vault_id, op, U128(amount)),
                );
        } else {
            v.withdrawing = amount;
            self.vaults.insert(&vault_id, &v);
            let _ = Promise::new(target)
                .function_call("withdraw", amount_args(amount), NearToken::from_yoctonear(0), VAULT_GAS)
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(CALLBACK_GAS)
                        .on_withdraw(vault_id, U128(amount), op),
                );
        }
        event("withdraw", &format!("{{\"vault\":{vault_id},\"amount\":\"{amount}\"}}"));
    }

    /// Reads what the target holds for the pool, which sets the share price. The agent at any time; anyone
    /// once the last reading is older than `SYNC_FRESH_NS`, so others cannot keep the vault busy. Counts as
    /// agent activity only when the agent calls it.
    pub fn sync(&mut self, vault_id: u32) {
        let mut v = self.vault(vault_id);
        Adapter::from_code(v.adapter).require_built();
        let agent = env::predecessor_account_id() == self.current_agent();
        require!(
            agent || now() > v.synced_at.saturating_add(SYNC_FRESH_NS),
            "this vault was read less than an hour ago"
        );
        let op = start(&mut v);
        if agent {
            self.last_agent_call = now();
        }
        let target = v.target.clone();
        self.vaults.insert(&vault_id, &v);
        let args = self.account_args();
        let _ = Promise::new(target)
            .function_call("get_account_total_balance", args, NearToken::from_yoctonear(0), VAULT_GAS)
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_sync(vault_id, op));
    }

    // ---- exits ----

    /// Pays a cash note to the account its owner signed for. Only the agent, which pays the gas. Counts as
    /// agent activity. Shows the paid account and the cash tier, never a vault.
    pub fn pay_exit(&mut self, note: NoteInput, owner_sig: Base64VecU8, to: AccountId, expires_at: u64) {
        self.only_agent();
        require!(now() <= expires_at, "the owner's signature has expired");
        let nf = self.checked_exit(None, &note, &owner_sig, &to, 0, expires_at);
        let pk = self.fresh_owner_key(&note);
        self.pay_note(None, nf, pk, note.tier, to, 0, false);
        self.last_agent_call = now();
    }

    /// Pays an exit request already listed, checked when it was filed. Only the agent. Counts as agent
    /// activity. For a share note (`vault_id` set), the vault shows, as it did when the owner filed it.
    pub fn pay_request(&mut self, vault_id: Option<u32>, nf: Base64VecU8) {
        self.only_agent();
        let nf: [u8; 32] = fixed(&nf.0).unwrap_or_else(|| env::panic_str("bad nullifier length"));
        let found = |list: &[Request]| {
            list.iter().find(|r| r.nf == nf).map(|r| (r.to.clone(), r.tier, r.pk, r.min_amount, r.expires_at))
        };
        let (to, tier, pk, min_amount, expires_at) = match vault_id {
            Some(id) => found(&self.vault(id).requests),
            None => found(&self.cash.requests),
        }
        .unwrap_or_else(|| env::panic_str("no such request"));
        require!(now() <= expires_at, "the owner's signature has expired");
        require!(!self.nullifiers.contains(&nf), "note already spent");
        require!(!self.owner_keys.contains(&pk), "this owner key already served another note");
        self.pay_note(vault_id, nf, pk, tier, to, min_amount, false);
        self.last_agent_call = now();
    }

    /// Records that the owner of a note asked for its exit. Filed by the account it pays, which attaches the
    /// storage fee (given back when the request leaves the list). A cash note (`vault_id` null) is the normal
    /// case. A share note is the fallback for a holder the agent does not serve, and shows the vault. If a
    /// request still payable waits the escape delay, that list opens: anyone can pay its notes with
    /// `escape_exit`, and for a vault, bring its funds back.
    #[payable]
    pub fn request_exit(
        &mut self,
        vault_id: Option<u32>,
        note: NoteInput,
        owner_sig: Base64VecU8,
        to: AccountId,
        min_amount: U128,
        expires_at: u64,
    ) {
        require!(env::predecessor_account_id() == to, "an exit request is filed by the account it pays");
        let fee = env::attached_deposit().as_yoctonear();
        require!(
            fee >= REQUEST_BYTES.saturating_mul(env::storage_byte_cost().as_yoctonear()),
            "attach the storage fee of the request"
        );
        require!(now() < expires_at, "the owner's signature has expired");
        require!(expires_at <= now().saturating_add(MAX_REQUEST_LIFE_NS), "a request lasts at most 30 days");
        let nf = self.checked_exit(vault_id, &note, &owner_sig, &to, min_amount.0, expires_at);
        let cancels = self.requested.get(&nf).unwrap_or(0);
        require!(cancels < MAX_CANCELS, "this note's request was withdrawn too many times");
        let pk = self.fresh_owner_key(&note);
        let h = self.holders.get(&to).unwrap_or_else(|| env::panic_str("exits go only to an account that deposited"));
        let request = Request {
            nf,
            at: now(),
            to: to.clone(),
            tier: note.tier,
            pk,
            min_amount: min_amount.0,
            expires_at,
            fee,
            payer: env::predecessor_account_id(),
        };
        let v = vault_id.map(|id| self.vault(id));
        let list = match &v {
            Some(v) => &v.requests,
            None => &self.cash.requests,
        };
        require!(!list.iter().any(|r| r.nf == nf), "exit already requested");
        require!(self.payable(v.as_ref(), &request), "this exit could not be paid");
        let waiting: u128 = list
            .iter()
            .filter(|r| r.to == to)
            .map(|r| self.value_of(v.as_ref(), r.tier))
            .fold(self.value_of(v.as_ref(), note.tier), u128::saturating_add);
        require!(waiting <= self.exit_limit(&h), "this account's waiting exits exceed its exit limit");
        require!(
            list.iter().filter(|r| r.to == to).count() < MAX_REQUESTS_PER_ACCOUNT,
            "too many exit requests for this account"
        );
        require!(list.len() < MAX_REQUESTS, "too many exit requests waiting");
        self.held_fees = add(self.held_fees, fee);
        // The note is marked for good: it can now only leave the pool by an exit.
        self.requested.insert(&nf, &cancels);
        match (vault_id, v) {
            (Some(id), Some(mut v)) => {
                v.requests.push(request);
                track_full(&v.requests, &mut v.full_since);
                self.vaults.insert(&id, &v);
            }
            _ => {
                self.cash.requests.push(request);
                track_full(&self.cash.requests, &mut self.cash.full_since);
            }
        }
        self.require_solvent();
        event("exit_requested", "{}");
    }

    /// The account an exit request pays withdraws it and gets its fee back, less the note's permanent mark.
    /// After `MAX_CANCELS` withdrawals the note cannot be requested again.
    pub fn cancel_exit_request(&mut self, vault_id: Option<u32>, nf: Base64VecU8) {
        let nf: [u8; 32] = fixed(&nf.0).unwrap_or_else(|| env::panic_str("bad nullifier length"));
        let account = env::predecessor_account_id();
        let r = self.take_request(vault_id, |r| r.nf == nf && r.to == account);
        let r = r.unwrap_or_else(|| env::panic_str("no such request for this account"));
        let count = self.requested.get(&nf).unwrap_or(0);
        self.requested.insert(&nf, &(count + 1));
        self.give_back(r);
    }

    /// Anyone removes a request that has expired or could no longer be paid; its fee goes back to its account.
    pub fn drop_request(&mut self, vault_id: Option<u32>, nf: Base64VecU8) {
        let nf: [u8; 32] = fixed(&nf.0).unwrap_or_else(|| env::panic_str("bad nullifier length"));
        let v = vault_id.map(|id| self.vault(id));
        let list = match &v {
            Some(v) => &v.requests,
            None => &self.cash.requests,
        };
        let r = list.iter().find(|r| r.nf == nf).unwrap_or_else(|| env::panic_str("no such request"));
        require!(
            now() > r.expires_at || self.nullifiers.contains(&nf) || !self.payable(v.as_ref(), r),
            "this request can still be paid"
        );
        let r = self.take_request(vault_id, |r| r.nf == nf).unwrap_or_else(|| env::panic_str("no such request"));
        self.give_back(r);
    }

    /// The same exit, by anyone, once the list is open: for a cash note when the agent has been silent for the
    /// escape delay, an announcement is pending, or a cash request has waited that long; for a share note
    /// when its vault is open the same way.
    pub fn escape_exit(
        &mut self,
        vault_id: Option<u32>,
        note: NoteInput,
        owner_sig: Base64VecU8,
        to: AccountId,
        min_amount: U128,
        expires_at: u64,
    ) {
        let open = match vault_id {
            Some(id) => self.vault_open(&self.vault(id)),
            None => self.cash_open(),
        };
        require!(open, "the agent is still active");
        require!(now() <= expires_at, "the owner's signature has expired");
        let nf = self.checked_exit(vault_id, &note, &owner_sig, &to, min_amount.0, expires_at);
        // While the agent is still around, the escape serves the holders who asked, not whoever comes first; unless
        // the list has stayed full for the escape delay, which would otherwise keep everyone else from asking.
        if !self.agent_silent() {
            let (listed, full_too_long) = match vault_id {
                Some(id) => {
                    let v = self.vault(id);
                    (v.requests.iter().any(|r| r.nf == nf), self.full_too_long(&v.requests, v.full_since))
                }
                None => (
                    self.cash.requests.iter().any(|r| r.nf == nf),
                    self.full_too_long(&self.cash.requests, self.cash.full_since),
                ),
            };
            require!(
                listed || full_too_long,
                "only notes with an exit request leave by the escape while the agent is active"
            );
        }
        let pk = self.fresh_owner_key(&note);
        self.pay_note(vault_id, nf, pk, note.tier, to, min_amount.0, true);
    }

    /// Pays the agent the fee owed by a vault, from its liquid funds. The only payment to the agent: at most
    /// the fee charged on gains, which is zero unless the guardian sets a rate.
    pub fn claim_fees(&mut self, vault_id: u32) {
        self.only_agent();
        let mut v = self.vault(vault_id);
        let free = v.liquid.saturating_sub(self.reserved(&v, None));
        let amount = v.fee_owed.min(free);
        v.fee_owed -= amount;
        v.liquid -= amount;
        self.vaults.insert(&vault_id, &v);
        self.total_liquid -= amount;
        if amount > 0 {
            let _ = Promise::new(self.current_agent()).transfer(NearToken::from_yoctonear(amount));
        }
        self.require_solvent();
    }

    /// An exit or refund whose transfer came back is kept for its holder, who collects it here.
    pub fn claim_owed(&mut self) {
        let account = env::predecessor_account_id();
        let mut h = self.holders.get(&account).unwrap_or_else(|| env::panic_str("nothing owed"));
        let amount = core::mem::take(&mut h.owed);
        require!(amount > 0, "nothing owed");
        self.holders.insert(&account, &h);
        self.total_owed -= amount;
        let _ = Promise::new(account).transfer(NearToken::from_yoctonear(amount));
        self.require_solvent();
    }

    // ---- callbacks ----

    #[private]
    pub fn on_place(&mut self, vault_id: u32, amount: U128, op: u64) {
        let mut v = self.vault(vault_id);
        finish(&mut v, op);
        // A failed call returns its attached deposit to the pool.
        if env::promise_result_checked(0, 64).is_err() {
            v.placed = v.placed.saturating_sub(amount.0);
            v.liquid = add(v.liquid, amount.0);
            self.total_liquid = add(self.total_liquid, amount.0);
            event("place_failed", &format!("{{\"vault\":{vault_id}}}"));
        }
        self.vaults.insert(&vault_id, &v);
    }

    #[private]
    pub fn on_withdraw(&mut self, vault_id: u32, amount: U128, op: u64) {
        let mut v = self.vault(vault_id);
        if v.busy_op == op {
            v.withdrawing = 0;
        }
        finish(&mut v, op);
        if env::promise_result_checked(0, 64).is_ok() {
            v.placed = v.placed.saturating_sub(amount.0);
            v.liquid = add(v.liquid, amount.0);
            self.total_liquid = add(self.total_liquid, amount.0);
        }
        self.vaults.insert(&vault_id, &v);
    }

    /// Second step of an `unstake` whose amount the contract fixed, with the target's unstaked (result 0) and
    /// staked (result 1) balances: asks for at most what is staked, and nothing while unstaked funds wait to be
    /// withdrawn, since a new `unstake` may push back their release (not verified): `withdraw` must come first.
    /// A failed or late reading frees the vault and starts no interval.
    #[private]
    pub fn on_staked_read(&mut self, vault_id: u32, op: u64, amount: U128) {
        let mut v = self.vault(vault_id);
        let read = |i: u64| env::promise_result_checked(i, 64).ok().and_then(|b| parse_u128(&b));
        let ask = match (read(0), read(1)) {
            (Some(0), Some(staked)) => staked.min(amount.0),
            (Some(_), Some(_)) => {
                event("unstake_waits", &format!("{{\"vault\":{vault_id}}}"));
                0
            }
            _ => 0,
        };
        if v.busy_op != op || ask == 0 {
            finish(&mut v, op);
            self.vaults.insert(&vault_id, &v);
            return;
        }
        let _ = Promise::new(v.target.clone())
            .function_call("unstake", amount_args(ask), NearToken::from_yoctonear(0), VAULT_GAS)
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_unstake(vault_id, op, true));
    }

    /// Second step of a `withdraw` whose amount the contract fixed: asks for at most what the target reports as
    /// already unstaked.
    #[private]
    pub fn on_unstaked_read(&mut self, vault_id: u32, op: u64, amount: U128) {
        let mut v = self.vault(vault_id);
        let reading = env::promise_result_checked(0, 64).ok().and_then(|b| parse_u128(&b));
        let ask = reading.map_or(0, |unstaked| unstaked.min(amount.0));
        if v.busy_op != op || ask == 0 {
            finish(&mut v, op);
            self.vaults.insert(&vault_id, &v);
            return;
        }
        v.withdrawing = ask;
        let target = v.target.clone();
        self.vaults.insert(&vault_id, &v);
        let _ = Promise::new(target)
            .function_call("withdraw", amount_args(ask), NearToken::from_yoctonear(0), VAULT_GAS)
            .then(
                Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_withdraw(vault_id, U128(ask), op),
            );
    }

    /// Only a successful `unstake` starts the interval.
    #[private]
    pub fn on_unstake(&mut self, vault_id: u32, op: u64, forced: bool) {
        let mut v = self.vault(vault_id);
        let current = v.busy_op == op;
        finish(&mut v, op);
        if current && env::promise_result_checked(0, 64).is_ok() {
            if forced {
                v.last_forced_unstake = now().max(1);
            } else {
                v.last_unstake = now().max(1);
            }
        }
        self.vaults.insert(&vault_id, &v);
    }

    #[private]
    pub fn on_sync(&mut self, vault_id: u32, op: u64) {
        let mut v = self.vault(vault_id);
        // A late answer may predate a placement or withdrawal since: only the current sync sets the balance.
        let current = v.busy_op == op;
        finish(&mut v, op);
        let reading = env::promise_result_checked(0, 64).ok().and_then(|b| parse_u128(&b)).filter(|_| current);
        if let Some(total) = reading {
            // Gains since the last reading are charged at the rate in force when that reading was made.
            let rate = self.fee_at(v.synced_at);
            v.placed = total;
            let p = price(&v);
            if v.total_shares > 0 && p > v.peak && rate > 0 {
                let gain = mul(p - v.peak, v.total_shares);
                v.fee_owed = add(v.fee_owed, mul(gain, u128::from(rate)) / 10_000);
            }
            v.peak = v.peak.max(price(&v));
            orphan_rest(&mut v);
            v.synced_at = now();
            event("sync", &format!("{{\"vault\":{vault_id},\"placed\":\"{total}\"}}"));
        }
        self.vaults.insert(&vault_id, &v);
    }

    #[private]
    pub fn on_payout(&mut self, to: AccountId, amount: U128) {
        if env::promise_result_checked(0, 16).is_err() {
            let mut h = self.holders.get(&to).unwrap_or_default();
            h.owed = add(h.owed, amount.0);
            self.holders.insert(&to, &h);
            self.total_owed = add(self.total_owed, amount.0);
            event("payout_returned", "{}");
        }
    }

    // ---- views ----

    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            guardian: self.guardian.clone(),
            agent: self.current_agent(),
            pending_agent: self.pending_agent.as_ref().filter(|(_, at)| now() < *at).map(|(a, _)| a.clone()),
            admin_pending_until: self.admin_pending_until,
            admin_delay_ns: self.admin_delay_ns,
            network: self.network.clone(),
            escape_delay_ns: self.escape_delay_ns,
            last_agent_call: self.last_agent_call,
            escape_open: self.escape_open(),
            fee_bps: self.fee_at(now()),
            pending_fee_bps: self.pending_fee.filter(|(_, at)| now() < *at).map(|(bps, _)| bps),
            max_rate_bps: self.max_rate_bps,
            vault_count: self.vault_count,
        }
    }

    pub fn get_vault(&self, vault_id: u32) -> VaultView {
        let v = self.vault(vault_id);
        VaultView {
            adapter: Adapter::from_code(v.adapter).name().into(),
            target: v.target.clone(),
            code_hash: Base64VecU8(v.code_hash.to_vec()),
            tiers: v
                .tiers
                .iter()
                .map(|t| TierView {
                    shares: U128(t.shares),
                    pk_raw: Base64VecU8(t.pk_raw.clone()),
                    issued: t.issued,
                    paid: t.paid,
                })
                .collect(),
            liquid: U128(v.liquid),
            placed: U128(v.placed),
            withdrawing: U128(v.withdrawing),
            fee_owed: U128(v.fee_owed),
            total_shares: U128(v.total_shares),
            orphan: U128(v.orphan),
            share_price: U128(price(&v)),
            synced_at: v.synced_at,
            max_assets: U128(v.max_assets),
            hourly_cap: U128(v.hourly_cap),
            frozen: v.frozen,
            busy: v.busy_since != 0,
            busy_op: v.busy_op,
            requests: v.requests.len() as u32,
            open: self.vault_open(&v),
        }
    }

    pub fn get_cash(&self) -> CashView {
        let outstanding = self
            .cash
            .tiers
            .iter()
            .map(|t| t.value.saturating_mul(u128::from(t.issued - t.paid)))
            .fold(0u128, u128::saturating_add);
        CashView {
            tiers: self
                .cash
                .tiers
                .iter()
                .map(|t| CashTierView {
                    value: U128(t.value),
                    pk_raw: Base64VecU8(t.pk_raw.clone()),
                    issued: t.issued,
                    paid: t.paid,
                })
                .collect(),
            liquid: U128(self.cash.liquid),
            outstanding: U128(outstanding),
            hourly_cap: U128(self.cash.hourly_cap),
            requests: self.cash.requests.len() as u32,
            open: self.cash_open(),
        }
    }

    pub fn get_holder(&self, account: AccountId) -> HolderView {
        let h = self.holders.get(&account).unwrap_or_default();
        HolderView {
            deposited: U128(h.deposited),
            refunded: U128(h.refunded),
            issued: U128(h.issued),
            received: U128(h.received),
            owed: U128(h.owed),
            exit_limit: U128(self.exit_limit(&h)),
            refundable: U128(self.refundable(&h)),
        }
    }

    pub fn is_spent(&self, nf: Base64VecU8) -> bool {
        fixed::<32>(&nf.0).is_some_and(|nf| self.nullifiers.contains(&nf))
    }

    /// Open when the agent has done no placement, sync or paid exit for the escape delay, and while any
    /// guardian announcement is waiting to take effect.
    pub fn escape_open(&self) -> bool {
        self.agent_silent() || now() < self.admin_pending_until
    }

    pub fn reserve_status(&self) -> ReserveStatus {
        let balance = env::account_balance().as_yoctonear();
        ReserveStatus {
            balance: U128(balance),
            storage_cost: U128(self.storage_cost()),
            liquid: U128(self.total_liquid),
            cash: U128(self.cash.liquid),
            owed: U128(self.total_owed),
            unassigned: U128(self.unassigned),
            held_fees: U128(self.held_fees),
            solvent: balance >= self.needed(),
        }
    }
}

impl Pool {
    fn vault(&self, id: u32) -> Vault {
        self.vaults.get(&id).unwrap_or_else(|| env::panic_str("unknown vault"))
    }

    fn only_guardian(&self) {
        require!(env::predecessor_account_id() == self.guardian, "only the guardian");
    }

    fn only_agent(&self) {
        require!(env::predecessor_account_id() == self.current_agent(), "only the agent");
    }

    fn agent_silent(&self) -> bool {
        now() >= self.last_agent_call.saturating_add(self.escape_delay_ns)
    }

    /// The fee rate in force at time `t`.
    fn fee_at(&self, t: u64) -> u16 {
        match self.pending_fee {
            Some((bps, at)) if t >= at => bps,
            _ => self.fee_bps,
        }
    }

    /// The announced agent once its delay has passed, otherwise the previous one.
    fn current_agent(&self) -> AccountId {
        match &self.pending_agent {
            Some((next, at)) if now() >= *at => next.clone(),
            _ => self.agent.clone(),
        }
    }

    /// Starts the admin delay for a guardian announcement. Returns when it takes effect.
    fn announce(&mut self) -> u64 {
        let at = now().saturating_add(self.admin_delay_ns);
        self.admin_pending_until = self.admin_pending_until.max(at);
        at
    }

    /// What one note of `tier` is worth now: a cash note's value, or a share note's at the vault's price.
    fn value_of(&self, v: Option<&Vault>, tier: u8) -> u128 {
        match v {
            Some(v) => v.tiers.get(usize::from(tier)).map_or(0, |t| t.shares.saturating_mul(price(v))),
            None => self.cash.tiers.get(usize::from(tier)).map_or(0, |t| t.value),
        }
    }

    /// The note's tier has unpaid notes, the note is worth its fee and the owner's minimum, the signature has
    /// not expired, and the account's exit limit covers it. Liquid funds are not required.
    fn payable(&self, v: Option<&Vault>, r: &Request) -> bool {
        let (paid, issued) = match v {
            Some(v) => v.tiers.get(usize::from(r.tier)).map_or((0, 0), |t| (t.paid, t.issued)),
            None => self.cash.tiers.get(usize::from(r.tier)).map_or((0, 0), |t| (t.paid, t.issued)),
        };
        let amount = self.value_of(v, r.tier);
        let Some(h) = self.holders.get(&r.to) else {
            return false;
        };
        paid < issued
            && now() <= r.expires_at
            && !self.nullifiers.contains(&r.nf)
            && !self.owner_keys.contains(&r.pk)
            && amount > EXIT_STORAGE_FEE
            && amount - EXIT_STORAGE_FEE >= r.min_amount
            && amount <= self.exit_limit(&h)
    }

    /// The list is full now and has been full, without going back down to half, for the escape delay. Once it is
    /// no longer full, this stops: everyone else can ask again, and the escape serves listed notes only.
    fn full_too_long(&self, requests: &[Request], full_since: u64) -> bool {
        requests.len() >= MAX_REQUESTS && full_since != 0 && now() >= full_since.saturating_add(self.escape_delay_ns)
    }

    /// A payable request has waited the escape delay, or the list has stayed full that long.
    fn overdue(&self, v: Option<&Vault>, requests: &[Request], full_since: u64) -> bool {
        let t = now();
        self.full_too_long(requests, full_since)
            || requests.iter().any(|r| t >= r.at.saturating_add(self.escape_delay_ns) && self.payable(v, r))
    }

    fn cash_overdue(&self) -> bool {
        self.overdue(None, &self.cash.requests, self.cash.full_since)
    }

    fn cash_open(&self) -> bool {
        self.escape_open() || self.cash_overdue()
    }

    /// Anyone may bring this vault's funds back and pay its share notes: the escape is open, or one of its own
    /// requests is overdue.
    fn vault_open(&self, v: &Vault) -> bool {
        self.escape_open() || self.overdue(Some(v), &v.requests, v.full_since)
    }

    /// The amount of an `unstake` or `withdraw`: the agent's choice while the vault is not open, otherwise
    /// fixed. Everything placed when the agent is silent or the vault's list has stayed full for the escape
    /// delay (then any note may leave, so the funds must all come back); else what the vault's payable
    /// requests need beyond its liquid funds.
    fn call_amount(&self, v: &Vault, asked: Option<U128>) -> u128 {
        let amount = if !self.forced(v) {
            asked.unwrap_or_else(|| env::panic_str("amount must be given")).0.min(v.placed)
        } else {
            require!(self.vault_open(v), "only the agent while it is active");
            if self.agent_silent() || self.full_too_long(&v.requests, v.full_since) {
                v.placed
            } else {
                self.reserved(v, None).saturating_sub(v.liquid).min(v.placed)
            }
        };
        require!(amount > 0, "nothing to bring back");
        amount
    }

    /// `{"account_id": <this pool>}`, the argument of the staking pool's balance views.
    fn account_args(&self) -> Vec<u8> {
        format!("{{\"account_id\":\"{}\"}}", env::current_account_id()).into_bytes()
    }

    /// The contract fixes the amount of this call: the caller is not the agent, or the vault is open.
    fn forced(&self, v: &Vault) -> bool {
        env::predecessor_account_id() != self.current_agent() || self.vault_open(v)
    }

    /// What the payable exit requests on this vault are worth, except the one for `except`: liquid funds a
    /// leave or an exit without a request must leave in place.
    fn reserved(&self, v: &Vault, except: Option<&[u8; 32]>) -> u128 {
        v.requests
            .iter()
            .filter(|r| Some(&r.nf) != except && self.payable(Some(v), r))
            .map(|r| self.value_of(Some(v), r.tier))
            .fold(0u128, u128::saturating_add)
    }

    /// The account's deposits not refunded and not turned into cash.
    fn refundable(&self, h: &Holder) -> u128 {
        h.deposited.saturating_sub(h.refunded).saturating_sub(h.issued).min(self.unassigned)
    }

    /// Growth since `accrued_at`, at the yearly rate, of the account's cash still in the pool (issued minus
    /// received): money only deposited, never turned into cash, earns nothing. Rounded down when stored, up
    /// when only shown in the limit.
    fn growth(&self, h: &Holder, up: bool) -> u128 {
        let net = h.issued.saturating_sub(h.received);
        let elapsed = u128::from(now().saturating_sub(h.accrued_at).min(100 * YEAR_NS));
        let (num, den) = (u128::from(self.max_rate_bps) * elapsed, 10_000 * u128::from(YEAR_NS));
        if up {
            mul_div_up(net, num, den)
        } else {
            mul_div(net, num, den)
        }
    }

    /// Brings the account's growth up to date. Called before every change of its deposits, refunds or
    /// receipts, so growth is earned only by money still in the pool, not by money that went round again.
    fn accrue(&self, h: &mut Holder) {
        if h.accrued_at != 0 {
            h.accrued = h.accrued.saturating_add(self.growth(h, false));
        }
        h.accrued_at = now().max(1);
    }

    /// Deposits not refunded, plus the growth earned by the net balance over time, minus what exits paid.
    /// Rounded up. Saturates instead of failing.
    fn exit_limit(&self, h: &Holder) -> u128 {
        let pending = if h.accrued_at == 0 { 0 } else { self.growth(h, true) };
        h.deposited
            .saturating_sub(h.refunded)
            .saturating_add(h.accrued)
            .saturating_add(pending)
            .saturating_sub(h.received)
    }

    /// The note's mark stays; the rest of a request's fee goes back to the account that paid it.
    fn give_back(&mut self, r: Request) {
        self.held_fees -= r.fee;
        let kept = MARK_BYTES.saturating_mul(env::storage_byte_cost().as_yoctonear()).min(r.fee);
        if r.fee > kept {
            self.pay(r.payer, r.fee - kept);
        }
    }

    /// Refuses a note ever named in an exit request: such a note can only leave the pool by an exit.
    fn not_requested(&self, nf: &[u8; 32]) {
        require!(self.requested.get(nf).is_none(), "a note named in an exit request can only exit");
    }

    /// The note's owner key, refused if it already served another note.
    fn fresh_owner_key(&self, note: &NoteInput) -> [u8; 32] {
        let (pk, _, _) = parse_note(note);
        require!(!self.owner_keys.contains(&pk), "this owner key already served another note");
        pk
    }

    fn storage_cost(&self) -> u128 {
        u128::from(env::storage_usage()).saturating_mul(env::storage_byte_cost().as_yoctonear())
    }

    /// What the balance must cover: storage, the vaults' and the cash's liquid funds, returned payouts,
    /// unassigned deposits and the fees of waiting requests.
    fn needed(&self) -> u128 {
        self.storage_cost()
            .saturating_add(self.total_liquid)
            .saturating_add(self.cash.liquid)
            .saturating_add(self.total_owed)
            .saturating_add(self.unassigned)
            .saturating_add(self.held_fees)
    }

    fn require_solvent(&self) {
        require!(env::account_balance().as_yoctonear() >= self.needed(), "the pool would not cover what it holds");
    }

    /// Sends `amount`; if the transfer comes back, it is kept for the account (`claim_owed`).
    fn pay(&self, to: AccountId, amount: u128) {
        let _ = Promise::new(to.clone())
            .transfer(NearToken::from_yoctonear(amount))
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_payout(to, U128(amount)));
    }

    /// Removes the first request of the list that matches.
    fn take_request(&mut self, vault_id: Option<u32>, matches: impl Fn(&Request) -> bool) -> Option<Request> {
        match vault_id {
            Some(id) => {
                let mut v = self.vault(id);
                let i = v.requests.iter().position(&matches)?;
                let r = v.requests.remove(i);
                track_full(&v.requests, &mut v.full_since);
                self.vaults.insert(&id, &v);
                Some(r)
            }
            None => {
                let i = self.cash.requests.iter().position(&matches)?;
                let r = self.cash.requests.remove(i);
                track_full(&self.cash.requests, &mut self.cash.full_since);
                Some(r)
            }
        }
    }

    /// Checks a note against a tag and key, and its owner's signature on `digest(nf)`.
    fn check_note(
        &self,
        dst: &[u8],
        pk_raw: &[u8],
        nf: [u8; 32],
        note: &NoteInput,
        owner_sig: &Base64VecU8,
        digest: impl Fn(&[u8; 32]) -> [u8; 32],
    ) -> [u8; 32] {
        let (pk, nonce, sig) = parse_note(note);
        require!(!self.nullifiers.contains(&nf), "note already spent");
        let owner_sig: [u8; 64] = fixed(&owner_sig.0).unwrap_or_else(|| env::panic_str("bad owner signature length"));
        require!(owner_signed(&pk, &digest(&nf), &owner_sig), "bad owner signature");
        require!(bls_valid(&sig, &message(note.tier, &pk, &nonce), dst, pk_raw), "invalid note");
        nf
    }

    fn check_cash_note(&self, note: &NoteInput, owner_sig: &Base64VecU8, digest: impl Fn(&[u8; 32]) -> [u8; 32]) -> [u8; 32] {
        let t = self.cash.tiers.get(usize::from(note.tier)).unwrap_or_else(|| env::panic_str("unknown tier"));
        let (pk, nonce, _) = parse_note(note);
        let nf = cash_nullifier(note.tier, &pk, &nonce);
        self.check_note(&self.cash.dst, &t.pk_raw, nf, note, owner_sig, digest)
    }

    fn check_share_note(
        &self,
        v: &Vault,
        vault_id: u32,
        note: &NoteInput,
        owner_sig: &Base64VecU8,
        digest: impl Fn(&[u8; 32]) -> [u8; 32],
    ) -> [u8; 32] {
        let t = v.tiers.get(usize::from(note.tier)).unwrap_or_else(|| env::panic_str("unknown tier"));
        let (pk, nonce, _) = parse_note(note);
        let nf = note_nullifier(vault_id, note.tier, &pk, &nonce);
        self.check_note(&v.dst, &t.pk_raw, nf, note, owner_sig, digest)
    }

    /// Checks a note and its owner's exit signature: a cash note when `vault_id` is `None`.
    fn checked_exit(
        &self,
        vault_id: Option<u32>,
        note: &NoteInput,
        owner_sig: &Base64VecU8,
        to: &AccountId,
        min_amount: u128,
        expires_at: u64,
    ) -> [u8; 32] {
        let contract = env::current_account_id();
        match vault_id {
            None => self.check_cash_note(note, owner_sig, |nf| cash_exit_digest(&contract, nf, to, expires_at)),
            Some(id) => {
                let v = self.vault(id);
                self.check_share_note(&v, id, note, owner_sig, |nf| {
                    share_exit_digest(&contract, id, nf, to, min_amount, expires_at)
                })
            }
        }
    }

    /// Pays a checked note to `to`. A cash note from the cash's liquid funds, a share note from its vault's,
    /// at a price read within the hour.
    #[allow(clippy::too_many_arguments)]
    fn pay_note(
        &mut self,
        vault_id: Option<u32>,
        nf: [u8; 32],
        pk: [u8; 32],
        tier: u8,
        to: AccountId,
        min_amount: u128,
        escape: bool,
    ) {
        let expired = match vault_id {
            Some(id) => self.vault(id).requests.iter().any(|r| r.nf == nf && now() > r.expires_at),
            None => self.cash.requests.iter().any(|r| r.nf == nf && now() > r.expires_at),
        };
        require!(!expired, "the owner's signature has expired");
        let mut h = self.holders.get(&to).unwrap_or_else(|| env::panic_str("exits go only to an account that deposited"));
        let mut v = vault_id.map(|id| self.vault(id));
        if let Some(v) = &v {
            require!(fresh(v), "sync this vault first");
        }
        let amount = self.value_of(v.as_ref(), tier);
        let (paid, issued) = match &v {
            Some(v) => v.tiers.get(usize::from(tier)).map_or((0, 0), |t| (t.paid, t.issued)),
            None => self.cash.tiers.get(usize::from(tier)).map_or((0, 0), |t| (t.paid, t.issued)),
        };
        require!(paid < issued, "more exits than notes issued");
        if !escape && vault_id.is_none() {
            require!(issued - paid >= self.min_live_notes, "too few live notes in this tier: wait for more");
        }
        require!(amount > EXIT_STORAGE_FEE, "note worth too little");
        let payout = amount - EXIT_STORAGE_FEE;
        require!(payout >= min_amount, "below the owner's minimum");
        require!(amount <= self.exit_limit(&h), "over this account's exit limit");
        match &mut v {
            Some(v) => {
                require!(amount <= v.liquid, "not enough liquid funds in this vault");
                require!(
                    v.liquid - amount >= self.reserved(v, Some(&nf)),
                    "these funds are kept for the exit requests waiting on this vault"
                );
                let cap = v.hourly_cap;
                use_window(&mut v.exit_window, cap, amount);
            }
            None => {
                require!(amount <= self.cash.liquid, "not enough cash");
                let cap = self.cash.hourly_cap;
                use_window(&mut self.cash.exit_window, cap, amount);
            }
        }

        self.nullifiers.insert(&nf);
        self.owner_keys.insert(&pk);
        self.accrue(&mut h);
        let refund = match vault_id {
            Some(id) => {
                let mut v = v.unwrap_or_else(|| env::panic_str("unknown vault"));
                let shares = v.tiers[usize::from(tier)].shares;
                v.tiers[usize::from(tier)].paid += 1;
                v.total_shares -= shares;
                v.liquid -= amount;
                orphan_rest(&mut v);
                self.total_liquid -= amount;
                self.vaults.insert(&id, &v);
                let r = self.take_request(Some(id), |r| r.nf == nf);
                event("share_exit", &format!("{{\"vault\":{id},\"tier\":{tier}}}"));
                r
            }
            None => {
                self.cash.tiers[usize::from(tier)].paid += 1;
                self.cash.liquid -= amount;
                let r = self.take_request(None, |r| r.nf == nf);
                event("exit", &format!("{{\"tier\":{tier}}}"));
                r
            }
        };
        h.received = add(h.received, amount);
        self.holders.insert(&to, &h);
        self.pay(to, payout);
        if let Some(r) = refund {
            self.give_back(r);
        }
        self.require_solvent();
    }
}

#[cfg(test)]
mod tests {
    use super::{mul_div, mul_div_up};

    #[test]
    fn mul_div_is_exact_beyond_128_bits() {
        assert_eq!(mul_div(6, 5, 10), 3);
        assert_eq!(mul_div(7, 0, 0), 0);
        let big = 1u128 << 100;
        assert_eq!(mul_div(big, big, big), big);
        assert_eq!(mul_div(u128::MAX, u128::MAX - 1, u128::MAX), u128::MAX - 1);
        assert_eq!(mul_div(u128::MAX, 3, 7), u128::MAX / 7 * 3 + (u128::MAX % 7) * 3 / 7);
        assert_eq!(mul_div_up(7, 1, 2), 4);
        assert_eq!(mul_div_up(big, big, big), big);
        assert_eq!(mul_div_up(u128::MAX, 3, 7), u128::MAX / 7 * 3 + (u128::MAX % 7) * 3 / 7 + 1);
    }
}
