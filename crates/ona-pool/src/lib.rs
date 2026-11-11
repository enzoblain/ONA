//! `ona-pool`: the contract that holds the funds the agent places. Draft, not audited, testnet only.
//! See `../SPEC.md`.
//!
//! The account has no access key once created. Nothing can leave it except:
//! - a placement into a vault on the guardian's list, through the fixed methods of that vault's adapter;
//! - an exit paid against a valid share note, only to an account that called `deposit`, within that account's limit;
//! - while the escape is open, a refund to a depositor of money never given to a vault, within its deposits;
//! - the agent's fee, which is zero unless the guardian sets it.
//!
//! The agent is an account set by the guardian. Checking that its key lives in an attested enclave is done
//! outside this contract, and is not built yet.

use near_sdk::collections::{LookupMap, LookupSet};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise};

pub const MAX_VAULTS: u32 = 32;
pub const MAX_TIERS: usize = 8;
pub const MAX_ENTRY: u64 = 64;
pub const HOUR_NS: u64 = 3_600_000_000_000;
pub const DAY_NS: u64 = 24 * HOUR_NS;
/// Default delay after which anyone holding shares can get paid without the agent.
pub const DEFAULT_ESCAPE_DELAY_NS: u64 = 7 * DAY_NS;
/// Default and shortest wait between the guardian announcing a new agent or vault and its effect: at least
/// as long as a staking pool takes to return unstaked funds, so holders can leave before it.
pub const DEFAULT_ADMIN_DELAY_NS: u64 = 7 * DAY_NS;
pub const MIN_ADMIN_DELAY_NS: u64 = 7 * DAY_NS;
pub const MAX_REQUESTS_PER_ACCOUNT: usize = 4;
/// Stands for the pool's reserve in `settle_switch`: what a switch leaves over goes there, to nobody.
pub const SWITCH_RESERVE: u32 = u32::MAX;
/// At most one `unstake` per vault in this time. A design margin, not a measured lock length.
pub const UNSTAKE_INTERVAL_NS: u64 = 3 * DAY_NS;
/// Attached to `request_exit` and kept, for the storage of the request.
pub const REQUEST_STORAGE_FEE: u128 = 1_000_000_000_000_000_000_000;
pub const MAX_REQUESTS: usize = 64;
pub const MIN_ESCAPE_DELAY_NS: u64 = 60_000_000_000;
pub const MAX_ESCAPE_DELAY_NS: u64 = 30 * DAY_NS;
/// Price of one share in yoctoNEAR when a vault has no share yet. 10^6 shares make one NEAR.
pub const INITIAL_PRICE: u128 = 1_000_000_000_000_000_000;
/// Highest fee the guardian can set, in basis points of the gains. A design choice.
pub const MAX_FEE_BPS: u16 = 2_000;
/// Kept from each exit to pay for the storage of its nullifier.
pub const EXIT_STORAGE_FEE: u128 = 1_000_000_000_000_000_000_000;
/// Kept from each deposit to pay for the storage of the depositor's record.
pub const DEPOSIT_STORAGE_FEE: u128 = 1_000_000_000_000_000_000_000;
pub const MIN_DEPOSIT: u128 = 100_000_000_000_000_000_000_000;
/// Entries stop below this share price, and exit limits never assume a lower one.
pub const PRICE_FLOOR: u128 = INITIAL_PRICE / 1_000;
/// An operation on a vault whose callback never came back stops blocking the vault after this.
pub const BUSY_TIMEOUT_NS: u64 = HOUR_NS;
/// Gas given to each call into a vault, and to our own callback. Not measured on a real pool.
const VAULT_GAS: Gas = Gas::from_tgas(50);
const CALLBACK_GAS: Gas = Gas::from_tgas(20);
const PPM: u128 = 1_000_000;

const G1_LEN: usize = 48;
const G2_LEN: usize = 96;

/// Base field modulus of BLS12-381, most significant limb first. Same as `ona-mint`.
const P: [u64; 6] = [
    0x1a0111ea397fe69a,
    0x4b1ba7b6434bacd7,
    0x64774b84f38512bf,
    0x6730d2a0f6b0f624,
    0x1eabfffeb153ffff,
    0xb9feffffffffaaab,
];

const G1_GEN: [u8; 96] = hex96(
    b"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
);
const NEG_G1: [u8; 96] = hex96(
    b"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca",
);
const NEG_G2: [u8; 192] = hex192(
    b"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed0d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa",
);

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

const fn hex96(s: &[u8; 192]) -> [u8; 96] {
    let mut out = [0u8; 96];
    let mut i = 0;
    while i < 96 {
        out[i] = nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex192(s: &[u8; 384]) -> [u8; 192] {
    let mut out = [0u8; 192];
    let mut i = 0;
    while i < 192 {
        out[i] = nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// The kinds of protocol a vault can be. Only `Staking` has an adapter.
///
/// `Lending` is reserved: no lending interface has been checked against its source yet, so a lending vault
/// cannot be added. TODO: an adapter with `place`, `withdraw` and `balance` calls, once the target
/// protocol's methods are read from its published code.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Adapter {
    /// The standard NEAR staking pool: `deposit_and_stake`, `unstake`, `withdraw`,
    /// `get_account_total_balance`.
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

/// Notes asked for in exchange of a switched note: `count` notes of `tier` in the destination vault.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct SwitchOut {
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
    /// Asked back from the target, not yet confirmed by its callback.
    withdrawing: u128,
    fee_owed: u128,
    /// Value this vault owes other vaults for notes switched out, and is owed for notes switched in, not
    /// settled yet. Counted in the share price; the money moves only at `settle_switch`.
    owes: u128,
    due: u128,
    total_shares: u128,
    /// Highest and lowest share price seen. The fee is charged only above `peak`.
    peak: u128,
    low: u128,
    max_assets: u128,
    /// Applies separately to placements and to exits, so placing cannot hold up exits.
    hourly_cap: u128,
    place_window: Window,
    exit_window: Window,
    /// Exits paid through the escape have their own window, so normal exits cannot use it up.
    escape_window: Window,
    /// When the guardian's announcement takes effect: no entry or placement before.
    active_at: u64,
    /// Exits asked for by their owner and not paid yet.
    requests: Vec<Request>,
    frozen: bool,
    /// Zero, or when the operation waiting for a callback started.
    busy_since: u64,
    /// Number of the operation waiting for a callback. Only that operation's callback frees the vault.
    busy_op: u64,
    /// Last `unstake`, which may restart the target's lock on everything already unstaked.
    last_unstake: u64,
    /// Zero, or since when the request list has been full (see `track_full`).
    full_since: u64,
}

#[near(serializers = [borsh])]
pub struct Request {
    nf: [u8; 32],
    at: u64,
    to: AccountId,
    tier: u8,
    min_amount: u128,
}

#[near(serializers = [borsh])]
#[derive(Default)]
pub struct Window {
    hour: u64,
    used: u128,
}

#[near(serializers = [borsh])]
#[derive(Default)]
pub struct Holder {
    deposited: u128,
    /// Paid back by `refund_deposit`.
    refunded: u128,
    /// Paid by exits.
    withdrawn: u128,
    /// Deposits not yet paid back by a refund or an exit: the account's share in refunds.
    open: u128,
    /// Zero, or when the account asked for a refund.
    refund_requested_at: u64,
    /// Exits whose transfer came back, claimable by the holder.
    owed: u128,
}

#[near(serializers = [json])]
pub struct TierView {
    pub shares: U128,
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
    pub owes: U128,
    pub due: U128,
    pub total_shares: U128,
    pub share_price: U128,
    pub max_assets: U128,
    pub hourly_cap: U128,
    pub frozen: bool,
    pub busy: bool,
    pub busy_op: u64,
    pub requests: u32,
}

#[near(serializers = [json])]
pub struct HolderView {
    pub deposited: U128,
    pub refunded: U128,
    pub withdrawn: U128,
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
    pub vault_count: u32,
}

#[near(serializers = [json])]
pub struct ReserveStatus {
    pub balance: U128,
    pub storage_cost: U128,
    pub liquid: U128,
    pub owed: U128,
    /// Received by `deposit` and not yet given to a vault.
    pub unassigned: U128,
    /// Left over from switches, paid to nobody.
    pub reserve: U128,
    pub solvent: bool,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Pool {
    guardian: AccountId,
    agent: AccountId,
    network: String,
    escape_delay_ns: u64,
    last_agent_call: u64,
    fee_bps: u16,
    vault_count: u32,
    total_liquid: u128,
    total_owed: u128,
    /// Deposited and not yet given to a vault. Counted, never read from the balance, so a plain
    /// transfer or a withdrawal in flight cannot be given to a vault.
    unassigned: u128,
    /// Sum of every account's `open`.
    total_open: u128,
    vaults: LookupMap<u32, Vault>,
    keys: LookupSet<[u8; 32]>,
    holders: LookupMap<AccountId, Holder>,
    nullifiers: LookupSet<[u8; 32]>,
    /// When each note's exit was first requested, kept after a withdrawal of the request.
    first_requests: LookupMap<[u8; 32], u64>,
    /// Switched value one vault owes another (or the reserve), by `pair(from, to)`.
    debts: LookupMap<u64, u128>,
    /// Left over from switches, kept by the pool and paid to nobody.
    reserve: u128,
    /// A new agent announced by the guardian, and when it takes over.
    pending_agent: Option<(AccountId, u64)>,
    /// The escape stays open to everyone until every guardian announcement has taken effect.
    admin_pending_until: u64,
    admin_delay_ns: u64,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    env::sha256(data).try_into().unwrap_or_else(|_| env::panic_str("sha256 length"))
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
        "EVENT_JSON:{{\"standard\":\"ona-pool\",\"version\":\"1.0.0\",\"event\":\"{name}\",\"data\":{data}}}"
    ));
}

/// Domain tag for hashing a share note of one vault. Each vault has its own keys as well, because a
/// blind signer cannot see which tag a point was hashed with.
pub fn note_dst(network: &str, contract: &str, vault_id: u32) -> String {
    format!("ONA-POOL-V1:{network}:{contract}:{vault_id}:BLS12381G1_XMD:SHA-256_SSWU_RO_")
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

/// What the note owner signs: the pool, the vault, the note, the paid account and the least it accepts.
/// `SHA-256("ONA-POOL-EXIT-V1" || H(contract) || vault_id (u32 LE) || nf || H(to) || min_amount (u128 LE))`.
pub fn exit_digest(
    contract: &AccountId,
    vault_id: u32,
    nf: &[u8; 32],
    to: &AccountId,
    min_amount: u128,
) -> [u8; 32] {
    let mut d = Vec::with_capacity(132);
    d.extend_from_slice(b"ONA-POOL-EXIT-V1");
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(&vault_id.to_le_bytes());
    d.extend_from_slice(nf);
    d.extend_from_slice(&sha256(to.as_bytes()));
    d.extend_from_slice(&min_amount.to_le_bytes());
    sha256(&d)
}

/// What the note owner signs to move a note of `from` to new notes of `to_vault`.
/// `SHA-256("ONA-POOL-SWITCH-V1" || H(contract) || from (u32 LE) || nf || to_vault (u32 LE) || n (u32 LE) || (tier || count (u64 LE))*n)`.
pub fn switch_digest(contract: &AccountId, from: u32, nf: &[u8; 32], to_vault: u32, outputs: &[SwitchOut]) -> [u8; 32] {
    let mut d = Vec::with_capacity(94 + outputs.len() * 9);
    d.extend_from_slice(b"ONA-POOL-SWITCH-V1");
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(&from.to_le_bytes());
    d.extend_from_slice(nf);
    d.extend_from_slice(&to_vault.to_le_bytes());
    d.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
    for o in outputs {
        d.push(o.tier);
        d.extend_from_slice(&o.count.to_le_bytes());
    }
    sha256(&d)
}

/// RFC 9380 `expand_message_xmd` with SHA-256, for 128 output bytes. Same as `ona-mint`.
fn expand_message_xmd(msg: &[u8], dst: &[u8]) -> [u8; 128] {
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    let mut input = vec![0u8; 64];
    input.extend_from_slice(msg);
    input.extend_from_slice(&[0, 128, 0]);
    input.extend_from_slice(&dst_prime);
    let b0 = sha256(&input);

    let mut out = [0u8; 128];
    let mut prev = [0u8; 32];
    for i in 0..4u8 {
        let mut block = Vec::with_capacity(33 + dst_prime.len());
        for j in 0..32 {
            block.push(b0[j] ^ prev[j]);
        }
        block.push(i + 1);
        block.extend_from_slice(&dst_prime);
        prev = sha256(&block);
        out[usize::from(i) * 32..usize::from(i + 1) * 32].copy_from_slice(&prev);
    }
    out
}

fn reduce_mod_p(bytes: &[u8]) -> [u8; 48] {
    let mut r = [0u64; 6];
    for byte in bytes {
        for bit in (0..8).rev() {
            let mut carry = u64::from(byte >> bit & 1);
            for limb in r.iter_mut().rev() {
                let next = *limb >> 63;
                *limb = *limb << 1 | carry;
                carry = next;
            }
            if r >= P {
                let mut borrow = false;
                for i in (0..6).rev() {
                    let (a, b1) = r[i].overflowing_sub(P[i]);
                    let (a, b2) = a.overflowing_sub(u64::from(borrow));
                    r[i] = a;
                    borrow = b1 || b2;
                }
            }
        }
    }
    let mut out = [0u8; 48];
    for (i, limb) in r.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn hash_to_g1_raw(msg: &[u8], dst: &[u8]) -> Vec<u8> {
    let uniform = expand_message_xmd(msg, dst);
    let mut fps = Vec::with_capacity(96);
    fps.extend_from_slice(&reduce_mod_p(&uniform[..64]));
    fps.extend_from_slice(&reduce_mod_p(&uniform[64..]));
    let mapped = env::bls12381_map_fp_to_g1(&fps)
        .filter(|m| m.len() == 192)
        .unwrap_or_else(|| env::panic_str("map_fp_to_g1 failed"));
    let mut sum_input = Vec::with_capacity(194);
    sum_input.push(0);
    sum_input.extend_from_slice(&mapped[..96]);
    sum_input.push(0);
    sum_input.extend_from_slice(&mapped[96..192]);
    env::bls12381_p1_sum(&sum_input).unwrap_or_else(|| env::panic_str("p1_sum failed"))
}

fn decompress_g1(p: &[u8; G1_LEN]) -> Option<Vec<u8>> {
    if p[0] & 0x80 == 0 || p[0] & 0x40 != 0 {
        return None;
    }
    env::bls12381_p1_decompress(p).filter(|raw| raw.len() == 96)
}

fn pairing_ok(sig_raw: &[u8], point_raw: &[u8], pk_raw: &[u8]) -> bool {
    let mut input = Vec::with_capacity(576);
    input.extend_from_slice(sig_raw);
    input.extend_from_slice(&NEG_G2);
    input.extend_from_slice(point_raw);
    input.extend_from_slice(pk_raw);
    env::bls12381_pairing_check(&input).unwrap_or(false)
}

/// Checks a compressed G2 key and returns it uncompressed, as `ona-mint::new` does.
fn checked_key(pk: &[u8]) -> Vec<u8> {
    let pk: [u8; G2_LEN] = fixed(pk).unwrap_or_else(|| env::panic_str("bad key length"));
    require!(pk[0] & 0x80 != 0 && pk[0] & 0x40 == 0, "bad key flags");
    let pk_raw = env::bls12381_p2_decompress(pk)
        .filter(|raw| raw.len() == 192)
        .unwrap_or_else(|| env::panic_str("bad key"));
    let mut check = Vec::with_capacity(576);
    check.extend_from_slice(&G1_GEN);
    check.extend_from_slice(&pk_raw);
    check.extend_from_slice(&NEG_G1);
    check.extend_from_slice(&pk_raw);
    require!(env::bls12381_pairing_check(&check).unwrap_or(false), "key outside the subgroup");
    pk_raw
}

fn assets(v: &Vault) -> u128 {
    v.liquid.saturating_add(v.placed).saturating_add(v.due).saturating_sub(v.fee_owed).saturating_sub(v.owes)
}

/// Price rounded up, used to value notes a vault receives by a switch.
fn price_up(v: &Vault) -> u128 {
    if v.total_shares == 0 {
        INITIAL_PRICE
    } else {
        let a = assets(v);
        a / v.total_shares + u128::from(a % v.total_shares != 0)
    }
}

/// What a vault holds or is owed, less what it owes, for its asset cap.
fn held(v: &Vault) -> u128 {
    v.liquid.saturating_add(v.placed).saturating_add(v.due).saturating_sub(v.owes)
}

/// What the vault holds and is owed covers what it owes and its fee. New money never goes into a vault that
/// does not, so a new holder never pays an older debt.
fn covers_debts(v: &Vault) -> bool {
    v.liquid.saturating_add(v.placed).saturating_add(v.due) >= v.owes.saturating_add(v.fee_owed)
}

/// Key of the debt `from` owes `to`.
fn pair(from: u32, to: u32) -> u64 {
    u64::from(from) << 32 | u64::from(to)
}

/// Total assets over shares issued, rounded down, in yoctoNEAR per share.
fn price(v: &Vault) -> u128 {
    if v.total_shares == 0 {
        INITIAL_PRICE
    } else {
        assets(v) / v.total_shares
    }
}

fn observe(v: &mut Vault) {
    if v.total_shares > 0 {
        let p = price(v);
        v.peak = v.peak.max(p);
        v.low = v.low.min(p);
    }
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

/// `a * b / c` rounded down, without overflow, for `b <= c`.
fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    if c == 0 {
        return 0;
    }
    if let Some(p) = a.checked_mul(b) {
        return p / c;
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
    q
}

fn amount_args(amount: u128) -> Vec<u8> {
    format!("{{\"amount\":\"{amount}\"}}").into_bytes()
}

#[near]
impl Pool {
    /// `escape_delay_secs` and `admin_delay_secs` default to 7 days each, and must be between one minute and
    /// 30 days.
    #[init]
    pub fn new(
        guardian: AccountId,
        agent: AccountId,
        network: String,
        escape_delay_secs: Option<u64>,
        admin_delay_secs: Option<u64>,
    ) -> Self {
        let escape_delay_ns =
            delay_ns(escape_delay_secs, MIN_ESCAPE_DELAY_NS, "escape delay must be between one minute and 30 days");
        let admin_delay_ns =
            delay_ns(admin_delay_secs, MIN_ADMIN_DELAY_NS, "admin delay must be between 7 and 30 days");
        require!(guardian != agent, "guardian and agent must differ");
        Self {
            guardian,
            agent,
            pending_agent: None,
            admin_pending_until: 0,
            admin_delay_ns,
            network,
            escape_delay_ns,
            last_agent_call: env::block_timestamp(),
            fee_bps: 0,
            vault_count: 0,
            total_liquid: 0,
            total_owed: 0,
            unassigned: 0,
            total_open: 0,
            vaults: LookupMap::new(b"v".to_vec()),
            keys: LookupSet::new(b"k".to_vec()),
            holders: LookupMap::new(b"h".to_vec()),
            nullifiers: LookupSet::new(b"n".to_vec()),
            first_requests: LookupMap::new(b"q".to_vec()),
            debts: LookupMap::new(b"d".to_vec()),
            reserve: 0,
        }
    }

    // ---- depositors ----

    /// The only way to become an account that can receive exits: the caller and the attached amount are
    /// recorded by the contract itself. Nobody can declare a depositor for someone else. A deposit comes back
    /// only through exits, or through `refund_deposit` while the escape is open.
    #[payable]
    pub fn deposit(&mut self) {
        let account = env::predecessor_account_id();
        let attached = env::attached_deposit().as_yoctonear();
        require!(attached >= MIN_DEPOSIT, "deposit too small");
        let credited = attached - DEPOSIT_STORAGE_FEE;
        let mut h = self.holders.get(&account).unwrap_or_default();
        h.deposited = add(h.deposited, credited);
        h.open = add(h.open, credited);
        self.holders.insert(&account, &h);
        self.unassigned = add(self.unassigned, credited);
        self.total_open = add(self.total_open, credited);
        self.require_solvent();
        event("deposit", "{}");
    }

    /// Asks for a refund of money never given to a vault. If it is still possible after the escape delay,
    /// `refund_deposit` opens for this account even while the agent is active.
    pub fn request_refund(&mut self) {
        let account = env::predecessor_account_id();
        let mut h = self.holders.get(&account).unwrap_or_else(|| env::panic_str("not a depositor"));
        require!(h.open > 0, "nothing left to refund");
        require!(h.refund_requested_at == 0, "refund already requested");
        h.refund_requested_at = env::block_timestamp().max(1);
        self.holders.insert(&account, &h);
        event("refund_requested", "{}");
    }

    /// While the escape is open, or once this account's refund request has waited the escape delay, a
    /// depositor takes back money never given to a vault. The contract does not know whose money went to a
    /// vault, so each account gets at most its share of what is unassigned: its deposits not yet paid back,
    /// over everyone's. A refund lowers the account's exit limit by the same amount.
    pub fn refund_deposit(&mut self, amount: U128) {
        let account = env::predecessor_account_id();
        let mut h = self.holders.get(&account).unwrap_or_else(|| env::panic_str("not a depositor"));
        let requested = h.refund_requested_at != 0
            && env::block_timestamp() >= h.refund_requested_at.saturating_add(self.escape_delay_ns);
        require!(self.escape_open() || requested, "the agent is still active");
        require!(amount.0 > 0, "amount must be positive");
        require!(amount.0 <= self.refundable(&h), "more than this account's share of the unassigned funds");
        h.refunded = add(h.refunded, amount.0);
        h.open -= amount.0;
        if h.open == 0 {
            h.refund_requested_at = 0;
        }
        self.holders.insert(&account, &h);
        self.unassigned -= amount.0;
        self.total_open -= amount.0;
        let _ = Promise::new(account.clone()).transfer(NearToken::from_yoctonear(amount.0)).then(
            Self::ext(env::current_account_id())
                .with_static_gas(CALLBACK_GAS)
                .on_exit_payout(account, amount),
        );
        self.require_solvent();
        event("refund", "{}");
    }

    // ---- guardian ----

    /// Announces a checked vault. Returns its id. It takes entries and placements only after the admin delay,
    /// and the escape is open to everyone until then. `kind` is `staking` or `lending`. `code_hash` is the
    /// SHA-256 of the code the guardian checked at `target`; a contract cannot read another account's code, so
    /// it is recorded for anyone to compare, not verified here.
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
        require!(!tiers.is_empty() && tiers.len() <= MAX_TIERS, "bad tier count");
        require!(max_assets.0 > 0 && hourly_cap.0 > 0, "caps must be positive");
        let code_hash: [u8; 32] = fixed(&code_hash.0).unwrap_or_else(|| env::panic_str("bad code hash length"));

        let id = self.vault_count;
        let mut list = Vec::with_capacity(tiers.len());
        for t in &tiers {
            require!(t.shares.0 > 0, "a tier needs shares");
            let pk_raw = checked_key(&t.pk_g2.0);
            let tag = sha256(&t.pk_g2.0);
            require!(!self.keys.contains(&tag), "key already used");
            self.keys.insert(&tag);
            list.push(Tier { shares: t.shares.0, pk_raw, issued: 0, paid: 0 });
        }
        let dst = note_dst(&self.network, env::current_account_id().as_str(), id);
        require!(dst.len() <= 255, "DST too long");
        let active_at = self.announce();
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
                owes: 0,
                due: 0,
                total_shares: 0,
                peak: INITIAL_PRICE,
                low: INITIAL_PRICE,
                max_assets: max_assets.0,
                hourly_cap: hourly_cap.0,
                place_window: Window::default(),
                exit_window: Window::default(),
                escape_window: Window::default(),
                frozen: false,
                busy_since: 0,
                busy_op: 0,
                last_unstake: 0,
                full_since: 0,
                active_at,
                requests: Vec::new(),
            },
        );
        self.vault_count += 1;
        self.require_solvent();
        event("add_vault", &format!("{{\"id\":{id},\"kind\":\"{}\",\"target\":\"{target}\"}}", adapter.name()));
        id
    }

    /// Stops new entries and placements. Withdrawals and exits keep working.
    pub fn freeze_vault(&mut self, vault_id: u32) {
        self.only_guardian();
        let mut v = self.vault(vault_id);
        v.frozen = true;
        self.vaults.insert(&vault_id, &v);
        event("freeze_vault", &format!("{{\"id\":{vault_id}}}"));
    }

    /// Announces a new agent, which takes over after the admin delay. Until then the current agent keeps
    /// working and the escape is open to everyone. Does not restart the escape delay.
    pub fn set_agent(&mut self, agent: AccountId) {
        self.only_guardian();
        require!(agent != self.guardian, "guardian and agent must differ");
        self.agent = self.current_agent();
        let at = self.announce();
        self.pending_agent = Some((agent, at));
        event("set_agent", &format!("{{\"effective_at\":{at}}}"));
    }

    /// The agent's share of the gains above each vault's highest price, in basis points. Zero by default.
    pub fn set_fee_bps(&mut self, fee_bps: u16) {
        self.only_guardian();
        require!(fee_bps <= MAX_FEE_BPS, "fee too high");
        // Gains made before the change are not charged at the new rate.
        for id in 0..self.vault_count {
            let mut v = self.vault(id);
            observe(&mut v);
            self.vaults.insert(&id, &v);
        }
        self.fee_bps = fee_bps;
        event("set_fee", &format!("{{\"bps\":{fee_bps}}}"));
    }

    // ---- agent ----

    /// Gives deposited funds to a vault in exchange for `count` notes of `tier`, at the current share
    /// price. The agent then blind-signs the notes off chain. Names no depositor. Returns the cost.
    pub fn record_entry(&mut self, vault_id: u32, tier: u8, count: u64) -> U128 {
        self.only_agent();
        require!(count > 0 && count <= MAX_ENTRY, "count must be between 1 and 64");
        let mut v = self.vault(vault_id);
        require!(!v.frozen, "vault frozen");
        require!(env::block_timestamp() >= v.active_at, "vault not active yet");
        let p = price(&v);
        require!(p >= PRICE_FLOOR, "share price too low for new entries");
        require!(covers_debts(&v), "this vault owes more than it holds");
        let tier_shares = v.tiers.get(usize::from(tier)).unwrap_or_else(|| env::panic_str("unknown tier")).shares;
        let shares = mul(tier_shares, u128::from(count));
        let cost = mul(shares, p);
        require!(cost <= self.unassigned, "not enough unassigned funds");
        require!(add(held(&v), cost) <= v.max_assets, "vault cap reached");
        v.tiers[usize::from(tier)].issued += count;
        v.total_shares = add(v.total_shares, shares);
        v.liquid = add(v.liquid, cost);
        observe(&mut v);
        self.vaults.insert(&vault_id, &v);
        self.total_liquid = add(self.total_liquid, cost);
        self.unassigned -= cost;
        self.require_solvent();
        event("entry", &format!("{{\"vault\":{vault_id},\"tier\":{tier},\"count\":{count}}}"));
        U128(cost)
    }

    /// Stakes `amount` of the vault's liquid funds with its target. Counts as agent activity.
    pub fn place(&mut self, vault_id: u32, amount: U128) {
        self.only_agent();
        let mut v = self.vault(vault_id);
        Adapter::from_code(v.adapter).require_built();
        require!(!v.frozen, "vault frozen");
        require!(env::block_timestamp() >= v.active_at, "vault not active yet");
        require!(!self.overdue(&v), "an exit request on this vault is overdue");
        require!(!self.creditor_overdue(vault_id), "a vault this one owes is overdue");
        // Switched value is settled before new money goes out, so a later loss is not shifted onto it.
        require!(v.owes == 0, "settle switches out of this vault first");
        require!(amount.0 > 0 && amount.0 <= v.liquid, "amount above the vault's liquid funds");
        let cap = v.hourly_cap;
        use_window(&mut v.place_window, cap, amount.0);
        let op = start(&mut v);
        self.last_agent_call = env::block_timestamp();
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

    /// Asks the target to unstake. The agent while it is active, or anyone else once the escape is open or an
    /// exit request on this vault is overdue; the agent itself cannot then, so it cannot keep restarting the
    /// target's lock. At most once per `UNSTAKE_INTERVAL_NS` per vault, for the same reason.
    pub fn unstake(&mut self, vault_id: u32, amount: U128) {
        let mut v = self.vault(vault_id);
        if env::predecessor_account_id() == self.current_agent() {
            require!(
                !self.escape_open() && !self.overdue(&v) && !self.creditor_overdue(vault_id),
                "the escape is open on this vault"
            );
        } else {
            self.agent_or_escape(vault_id, &v);
        }
        Adapter::from_code(v.adapter).require_built();
        require!(amount.0 > 0, "amount must be positive");
        let now = env::block_timestamp();
        require!(
            v.last_unstake == 0 || now >= v.last_unstake.saturating_add(UNSTAKE_INTERVAL_NS),
            "unstaked too recently on this vault"
        );
        let op = start(&mut v);
        v.last_unstake = now.max(1);
        let target = v.target.clone();
        self.vaults.insert(&vault_id, &v);
        let _ = Promise::new(target)
            .function_call("unstake", amount_args(amount.0), NearToken::from_yoctonear(0), VAULT_GAS)
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_done(vault_id, op));
        event("unstake", &format!("{{\"vault\":{vault_id},\"amount\":\"{}\"}}", amount.0));
    }

    /// Brings unstaked funds back into the pool. The agent, or anyone once the escape is open or an exit
    /// request on this vault is overdue.
    pub fn withdraw(&mut self, vault_id: u32, amount: U128) {
        let mut v = self.vault(vault_id);
        self.agent_or_escape(vault_id, &v);
        Adapter::from_code(v.adapter).require_built();
        require!(amount.0 > 0 && amount.0 <= v.placed, "amount above what the vault holds");
        let op = start(&mut v);
        v.withdrawing = amount.0;
        let target = v.target.clone();
        self.vaults.insert(&vault_id, &v);
        let _ = Promise::new(target)
            .function_call("withdraw", amount_args(amount.0), NearToken::from_yoctonear(0), VAULT_GAS)
            .then(
                Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_withdraw(vault_id, amount, op),
            );
        event("withdraw", &format!("{{\"vault\":{vault_id},\"amount\":\"{}\"}}", amount.0));
    }

    /// Reads what the target holds for the pool, which sets the share price. The agent, or anyone once the
    /// escape is open or an exit request on this vault is overdue. Counts as agent activity when the agent calls it.
    pub fn sync(&mut self, vault_id: u32) {
        let mut v = self.vault(vault_id);
        self.agent_or_escape(vault_id, &v);
        Adapter::from_code(v.adapter).require_built();
        let op = start(&mut v);
        if env::predecessor_account_id() == self.current_agent() {
            self.last_agent_call = env::block_timestamp();
        }
        let target = v.target.clone();
        self.vaults.insert(&vault_id, &v);
        let args = format!("{{\"account_id\":\"{}\"}}", env::current_account_id()).into_bytes();
        let _ = Promise::new(target)
            .function_call("get_account_total_balance", args, NearToken::from_yoctonear(0), VAULT_GAS)
            .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_sync(vault_id, op));
    }

    /// Pays an exit. Only the agent, so that it pays the gas and the note owner signs nothing on chain. A paid
    /// exit counts as agent activity.
    pub fn pay_exit(&mut self, vault_id: u32, note: NoteInput, owner_sig: Base64VecU8, to: AccountId, min_amount: U128) {
        self.only_agent();
        self.exit(vault_id, note, owner_sig, to, min_amount.0, false);
        self.last_agent_call = env::block_timestamp();
    }

    /// Records that the owner of a note asked for its exit, by anyone, who attaches at least 0.001 NEAR for
    /// its storage (kept by the pool). If the agent has not paid it within the escape delay, `escape_exit`
    /// opens for this note, anyone can unstake and withdraw from this vault, and the agent cannot place in it.
    #[payable]
    pub fn request_exit(
        &mut self,
        vault_id: u32,
        note: NoteInput,
        owner_sig: Base64VecU8,
        to: AccountId,
        min_amount: U128,
    ) {
        require!(env::attached_deposit().as_yoctonear() >= REQUEST_STORAGE_FEE, "attach 0.001 NEAR for storage");
        let mut v = self.vault(vault_id);
        let nf = self.check_note(&v, vault_id, &note, &owner_sig, &to, min_amount.0);
        require!(self.holders.get(&to).is_some(), "exits go only to an account that deposited");
        require!(!v.requests.iter().any(|r| r.nf == nf), "exit already requested");
        // A note keeps the date of its first request, even if the request was withdrawn and made again.
        let at = self.first_requests.get(&nf).unwrap_or_else(|| {
            self.first_requests.insert(&nf, &env::block_timestamp());
            env::block_timestamp()
        });
        let request = Request { nf, at, to: to.clone(), tier: note.tier, min_amount: min_amount.0 };
        require!(self.payable(&v, &request), "this exit could not be paid");
        require!(
            v.requests.iter().filter(|r| r.to == to).count() < MAX_REQUESTS_PER_ACCOUNT,
            "too many exit requests for this account"
        );
        require!(v.requests.len() < MAX_REQUESTS, "too many exit requests waiting on this vault");
        v.requests.push(request);
        track_full(&mut v);
        self.vaults.insert(&vault_id, &v);
        self.require_solvent();
        event("exit_requested", &format!("{{\"vault\":{vault_id}}}"));
    }

    /// The account an exit request pays withdraws it.
    pub fn cancel_exit_request(&mut self, vault_id: u32, nf: Base64VecU8) {
        let nf: [u8; 32] = fixed(&nf.0).unwrap_or_else(|| env::panic_str("bad nullifier length"));
        let mut v = self.vault(vault_id);
        let account = env::predecessor_account_id();
        let before = v.requests.len();
        v.requests.retain(|r| !(r.nf == nf && r.to == account));
        require!(v.requests.len() < before, "no such request for this account");
        track_full(&mut v);
        self.vaults.insert(&vault_id, &v);
    }

    /// The same exit, by anyone, once the agent has been silent for the escape delay, or on a vault where a
    /// payable exit request has waited that long, or whose request list has stayed full that long.
    pub fn escape_exit(
        &mut self,
        vault_id: u32,
        note: NoteInput,
        owner_sig: Base64VecU8,
        to: AccountId,
        min_amount: U128,
    ) {
        let open = self.escape_open() || self.overdue(&self.vault(vault_id));
        require!(open, "the agent is still active");
        self.exit(vault_id, note, owner_sig, to, min_amount.0, true);
    }

    /// Moves one note of `from` to new notes of `to_vault`, with no payment to anyone. The note is checked
    /// and spent as for an exit, signed by its owner for exactly these outputs, and must have no exit request
    /// waiting. The note is valued at `from`'s price rounded down, the new notes at `to_vault`'s price rounded
    /// up; what is left over must be less than the smallest note of `to_vault` and goes to the pool's reserve,
    /// so no share price jumps. The agent then blind-signs the new notes off chain. `from` now owes the cost
    /// to `to_vault` and the rest to the reserve, settled later by `settle_switch`. Only the agent, which pays
    /// the gas; no account's counters change. Returns the cost of the new notes.
    pub fn switch_vault(
        &mut self,
        from: u32,
        note: NoteInput,
        owner_sig: Base64VecU8,
        to_vault: u32,
        outputs: Vec<SwitchOut>,
    ) -> U128 {
        self.only_agent();
        require!(from != to_vault, "choose another vault");
        require!(!outputs.is_empty() && outputs.len() <= MAX_TIERS, "bad output count");
        let mut a = self.vault(from);
        let mut b = self.vault(to_vault);
        require!(!b.frozen, "vault frozen");
        require!(env::block_timestamp() >= b.active_at, "vault not active yet");
        let contract = env::current_account_id();
        let nf = self.check_signed_note(&a, from, &note, &owner_sig, |nf| {
            switch_digest(&contract, from, nf, to_vault, &outputs)
        });
        require!(!a.requests.iter().any(|r| r.nf == nf), "withdraw the exit request on this note first");
        let t = &a.tiers[usize::from(note.tier)];
        require!(t.paid < t.issued, "more exits than notes issued");
        let shares_a = t.shares;
        let value = shares_a.saturating_mul(price(&a));

        require!(price(&b) >= PRICE_FLOOR, "share price too low for new entries");
        require!(covers_debts(&b), "this vault owes more than it holds");
        let pb = price_up(&b);
        let (mut shares_b, mut total_count) = (0u128, 0u64);
        for o in &outputs {
            let tb = b.tiers.get(usize::from(o.tier)).unwrap_or_else(|| env::panic_str("unknown tier"));
            require!(o.count > 0, "count must be positive");
            total_count = total_count.saturating_add(o.count);
            shares_b = add(shares_b, mul(tb.shares, u128::from(o.count)));
        }
        require!(total_count <= MAX_ENTRY, "count must be between 1 and 64");
        let cost = mul(shares_b, pb);
        require!(cost <= value, "the new notes are worth more than the note");
        let smallest = b.tiers.iter().map(|t| t.shares).min().unwrap_or(0).saturating_mul(pb);
        let rest = value - cost;
        require!(rest < smallest, "too much left over: ask for more notes");
        require!(add(held(&b), cost) <= b.max_assets, "vault cap reached");

        self.nullifiers.insert(&nf);
        track_full(&mut a);
        a.tiers[usize::from(note.tier)].paid += 1;
        a.total_shares -= shares_a;
        a.owes = add(a.owes, value);
        observe(&mut a);
        self.add_debt(from, to_vault, cost);
        if rest > 0 {
            self.add_debt(from, SWITCH_RESERVE, rest);
        }
        for o in &outputs {
            b.tiers[usize::from(o.tier)].issued += o.count;
        }
        b.total_shares = add(b.total_shares, shares_b);
        b.due = add(b.due, cost);
        observe(&mut b);
        self.vaults.insert(&from, &a);
        self.vaults.insert(&to_vault, &b);
        self.require_solvent();
        event("switch", &format!("{{\"from\":{from},\"to\":{to_vault}}}"));
        U128(cost)
    }

    /// Moves liquid funds `from` owes `to_vault` for switched notes, or owes the reserve when `to_vault` is
    /// `SWITCH_RESERVE`. Money stays in the pool. The agent, or anyone once the escape is open, `from` is
    /// overdue, or a vault `from` owes is overdue.
    pub fn settle_switch(&mut self, from: u32, to_vault: u32, amount: U128) {
        let mut a = self.vault(from);
        self.agent_or_escape(from, &a);
        require!(from != to_vault, "choose another vault");
        let owed = self.debt(from, to_vault);
        require!(owed > 0, "this vault owes nothing to that one");
        require!(amount.0 > 0 && amount.0 <= owed, "more than is owed between these vaults");
        require!(amount.0 <= a.liquid, "not enough liquid funds in this vault");
        a.liquid -= amount.0;
        a.owes -= amount.0;
        self.vaults.insert(&from, &a);
        if owed == amount.0 {
            self.debts.remove(&pair(from, to_vault));
        } else {
            self.debts.insert(&pair(from, to_vault), &(owed - amount.0));
        }
        if to_vault == SWITCH_RESERVE {
            self.total_liquid -= amount.0;
            self.reserve = add(self.reserve, amount.0);
        } else {
            let mut b = self.vault(to_vault);
            b.liquid = add(b.liquid, amount.0);
            b.due -= amount.0;
            self.vaults.insert(&to_vault, &b);
        }
        event("settle_switch", &format!("{{\"from\":{from},\"to\":{to_vault}}}"));
    }

    /// Pays the agent the fee owed by a vault, from its liquid funds. The only payment to the agent: at most
    /// the fee charged on gains, which is zero unless the guardian sets a rate.
    pub fn claim_fees(&mut self, vault_id: u32) {
        self.only_agent();
        let mut v = self.vault(vault_id);
        let amount = v.fee_owed.min(v.liquid);
        v.fee_owed -= amount;
        v.liquid -= amount;
        self.vaults.insert(&vault_id, &v);
        self.total_liquid -= amount;
        if amount > 0 {
            let _ = Promise::new(self.current_agent()).transfer(NearToken::from_yoctonear(amount));
        }
        self.require_solvent();
    }

    /// An exit whose transfer came back is kept for its holder, who collects it here.
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

    #[private]
    pub fn on_sync(&mut self, vault_id: u32, op: u64) {
        let mut v = self.vault(vault_id);
        // A late answer may predate a placement or withdrawal since: only the current sync sets the balance.
        let current = v.busy_op == op;
        finish(&mut v, op);
        let reading = env::promise_result_checked(0, 64).ok().and_then(|b| parse_u128(&b)).filter(|_| current);
        if let Some(total) = reading {
            v.placed = total;
            let p = price(&v);
            if v.total_shares > 0 && p > v.peak && self.fee_bps > 0 {
                let gain = mul(p - v.peak, v.total_shares);
                v.fee_owed = add(v.fee_owed, mul(gain, u128::from(self.fee_bps)) / 10_000);
            }
            observe(&mut v);
            event("sync", &format!("{{\"vault\":{vault_id},\"placed\":\"{total}\"}}"));
        }
        self.vaults.insert(&vault_id, &v);
    }

    #[private]
    pub fn on_done(&mut self, vault_id: u32, op: u64) {
        let mut v = self.vault(vault_id);
        finish(&mut v, op);
        self.vaults.insert(&vault_id, &v);
    }

    #[private]
    pub fn on_exit_payout(&mut self, to: AccountId, amount: U128) {
        if env::promise_result_checked(0, 16).is_err() {
            let mut h = self.holders.get(&to).unwrap_or_default();
            h.owed = add(h.owed, amount.0);
            self.holders.insert(&to, &h);
            self.total_owed = add(self.total_owed, amount.0);
            event("exit_returned", "{}");
        }
    }

    // ---- views ----

    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            guardian: self.guardian.clone(),
            agent: self.current_agent(),
            pending_agent: self
                .pending_agent
                .as_ref()
                .filter(|(_, at)| env::block_timestamp() < *at)
                .map(|(a, _)| a.clone()),
            admin_pending_until: self.admin_pending_until,
            admin_delay_ns: self.admin_delay_ns,
            network: self.network.clone(),
            escape_delay_ns: self.escape_delay_ns,
            last_agent_call: self.last_agent_call,
            escape_open: self.escape_open(),
            fee_bps: self.fee_bps,
            vault_count: self.vault_count,
        }
    }

    pub fn get_vault(&self, vault_id: u32) -> VaultView {
        let v = self.vault(vault_id);
        VaultView {
            adapter: Adapter::from_code(v.adapter).name().into(),
            target: v.target.clone(),
            code_hash: Base64VecU8(v.code_hash.to_vec()),
            withdrawing: U128(v.withdrawing),
            tiers: v
                .tiers
                .iter()
                .map(|t| TierView { shares: U128(t.shares), issued: t.issued, paid: t.paid })
                .collect(),
            liquid: U128(v.liquid),
            placed: U128(v.placed),
            fee_owed: U128(v.fee_owed),
            owes: U128(v.owes),
            due: U128(v.due),
            total_shares: U128(v.total_shares),
            share_price: U128(price(&v)),
            max_assets: U128(v.max_assets),
            hourly_cap: U128(v.hourly_cap),
            frozen: v.frozen,
            busy: v.busy_since != 0,
            busy_op: v.busy_op,
            requests: v.requests.len() as u32,
        }
    }

    pub fn get_holder(&self, account: AccountId) -> HolderView {
        let h = self.holders.get(&account).unwrap_or_default();
        HolderView {
            deposited: U128(h.deposited),
            refunded: U128(h.refunded),
            withdrawn: U128(h.withdrawn),
            owed: U128(h.owed),
            exit_limit: U128(self.exit_limit(&h)),
            refundable: U128(self.refundable(&h)),
        }
    }

    /// Switched value `from` owes `to` (`SWITCH_RESERVE` for the reserve), not settled yet.
    pub fn get_debt(&self, from: u32, to: u32) -> U128 {
        U128(self.debt(from, to))
    }

    pub fn is_spent(&self, nf: Base64VecU8) -> bool {
        fixed::<32>(&nf.0).is_some_and(|nf| self.nullifiers.contains(&nf))
    }

    /// Open when the agent has done no placement, sync or paid exit for the escape delay, and while any
    /// guardian announcement is waiting to take effect.
    pub fn escape_open(&self) -> bool {
        let now = env::block_timestamp();
        now >= self.last_agent_call.saturating_add(self.escape_delay_ns) || now < self.admin_pending_until
    }

    pub fn reserve_status(&self) -> ReserveStatus {
        let storage_cost = self.storage_cost();
        let balance = env::account_balance().as_yoctonear();
        ReserveStatus {
            balance: U128(balance),
            storage_cost: U128(storage_cost),
            liquid: U128(self.total_liquid),
            owed: U128(self.total_owed),
            unassigned: U128(self.unassigned),
            reserve: U128(self.reserve),
            solvent: balance >= self.needed(),
        }
    }
}

fn use_window(w: &mut Window, cap: u128, amount: u128) {
    let hour = env::block_timestamp() / HOUR_NS;
    if hour != w.hour {
        w.hour = hour;
        w.used = 0;
    }
    let used = add(w.used, amount);
    require!(used <= cap, "hourly limit reached for this vault");
    w.used = used;
}

/// Starts the clock when the request list fills up, and stops it only once the list is down to half: a
/// request withdrawn and made again does not restart it.
fn track_full(v: &mut Vault) {
    if v.requests.len() >= MAX_REQUESTS {
        if v.full_since == 0 {
            v.full_since = env::block_timestamp().max(1);
        }
    } else if v.requests.len() <= MAX_REQUESTS / 2 {
        v.full_since = 0;
    }
}

/// Marks the vault busy with a new operation and returns its number.
fn start(v: &mut Vault) -> u64 {
    let now = env::block_timestamp();
    require!(
        v.busy_since == 0 || now >= v.busy_since.saturating_add(BUSY_TIMEOUT_NS),
        "an operation on this vault is still running"
    );
    v.busy_since = now.max(1);
    v.busy_op += 1;
    v.busy_op
}

/// Frees the vault, only if `op` is the operation it is busy with: a late callback of an operation that
/// timed out cannot free the vault from the one that replaced it.
fn finish(v: &mut Vault, op: u64) {
    if v.busy_op == op {
        v.busy_since = 0;
    }
}

impl Pool {
    fn vault(&self, id: u32) -> Vault {
        self.vaults.get(&id).unwrap_or_else(|| env::panic_str("unknown vault"))
    }

    fn only_guardian(&self) {
        require!(env::predecessor_account_id() == self.guardian, "only the guardian");
    }

    /// Agent work that does not count as activity for the escape (entries, unstaking, withdrawals, fees) uses
    /// this. Only placements, syncs and paid exits restart the escape delay.
    fn only_agent(&self) {
        require!(env::predecessor_account_id() == self.current_agent(), "only the agent");
    }

    fn agent_or_escape(&self, vault_id: u32, v: &Vault) {
        if env::predecessor_account_id() != self.current_agent() {
            require!(
                self.escape_open() || self.overdue(v) || self.creditor_overdue(vault_id),
                "only the agent while it is active"
            );
        }
    }

    /// A vault that `vault_id` owes switched value to is overdue: its funds must be reachable to pay it.
    fn creditor_overdue(&self, vault_id: u32) -> bool {
        (0..self.vault_count).any(|id| {
            id != vault_id
                && self.debt(vault_id, id) > 0
                && self.vaults.get(&id).is_some_and(|b| self.overdue(&b))
        })
    }

    fn debt(&self, from: u32, to: u32) -> u128 {
        self.debts.get(&pair(from, to)).unwrap_or(0)
    }

    fn add_debt(&mut self, from: u32, to: u32, amount: u128) {
        let total = add(self.debt(from, to), amount);
        self.debts.insert(&pair(from, to), &total);
    }

    /// The announced agent once its delay has passed, otherwise the previous one.
    fn current_agent(&self) -> AccountId {
        match &self.pending_agent {
            Some((next, at)) if env::block_timestamp() >= *at => next.clone(),
            _ => self.agent.clone(),
        }
    }

    /// Starts the admin delay for a guardian announcement. Returns when it takes effect.
    fn announce(&mut self) -> u64 {
        let at = env::block_timestamp().saturating_add(self.admin_delay_ns);
        self.admin_pending_until = self.admin_pending_until.max(at);
        at
    }

    /// An exit asked for on this vault, and still payable, has waited longer than the escape delay. A request
    /// that could no longer be paid, for instance after a loss, does not block the vault.
    /// A list kept full for the escape delay counts too, so it cannot be used to keep honest holders out.
    fn overdue(&self, v: &Vault) -> bool {
        let now = env::block_timestamp();
        (v.full_since != 0 && now >= v.full_since.saturating_add(self.escape_delay_ns))
            || v.requests
                .iter()
                .any(|r| now >= r.at.saturating_add(self.escape_delay_ns) && self.payable(v, r))
    }

    /// The note's tier exists, it is worth more than the storage fee and at least the owner's minimum, and
    /// the account's exit limit covers it. Liquid funds are not required: they can be withdrawn.
    fn payable(&self, v: &Vault, r: &Request) -> bool {
        let Some(t) = v.tiers.get(usize::from(r.tier)) else {
            return false;
        };
        let amount = t.shares.saturating_mul(price(v));
        let Some(h) = self.holders.get(&r.to) else {
            return false;
        };
        t.paid < t.issued
            && amount > EXIT_STORAGE_FEE
            && amount - EXIT_STORAGE_FEE >= r.min_amount
            && amount <= self.exit_limit(&h)
    }

    /// The account's share of the unassigned funds: its open deposits over everyone's.
    fn refundable(&self, h: &Holder) -> u128 {
        mul_div(h.open, self.unassigned, self.total_open).min(self.unassigned).min(h.open)
    }

    fn storage_cost(&self) -> u128 {
        u128::from(env::storage_usage()).saturating_mul(env::storage_byte_cost().as_yoctonear())
    }

    /// What the balance must cover: storage, the vaults' liquid funds, returned exits, unassigned deposits.
    fn needed(&self) -> u128 {
        self.storage_cost()
            .saturating_add(self.total_liquid)
            .saturating_add(self.total_owed)
            .saturating_add(self.unassigned)
            .saturating_add(self.reserve)
    }

    fn require_solvent(&self) {
        require!(env::account_balance().as_yoctonear() >= self.needed(), "the pool would not cover what it holds");
    }

    /// Highest growth of any vault's share price, from its lowest (never below `PRICE_FLOOR`) to its highest,
    /// in millionths. The contract does not know which vault an account chose, so it allows the best case.
    fn max_growth_ppm(&self) -> u128 {
        let mut best = PPM;
        for id in 0..self.vault_count {
            if let Some(v) = self.vaults.get(&id) {
                best = best.max(v.peak.saturating_mul(PPM) / v.low.max(PRICE_FLOOR));
            }
        }
        best
    }

    /// Deposits not refunded, times the best growth, minus what exits already paid. Saturates instead of failing.
    fn exit_limit(&self, h: &Holder) -> u128 {
        let g = self.max_growth_ppm();
        let base = h.deposited.saturating_sub(h.refunded);
        let grown = (base / PPM).saturating_mul(g).saturating_add((base % PPM).saturating_mul(g) / PPM);
        grown.saturating_sub(h.withdrawn)
    }

    /// Checks a note and its owner's signature for an exit to `to`. Returns its nullifier.
    fn check_note(
        &self,
        v: &Vault,
        vault_id: u32,
        note: &NoteInput,
        owner_sig: &Base64VecU8,
        to: &AccountId,
        min_amount: u128,
    ) -> [u8; 32] {
        let contract = env::current_account_id();
        self.check_signed_note(v, vault_id, note, owner_sig, |nf| exit_digest(&contract, vault_id, nf, to, min_amount))
    }

    /// Checks a note, and its owner's signature on the digest `digest` builds from its nullifier.
    fn check_signed_note(
        &self,
        v: &Vault,
        vault_id: u32,
        note: &NoteInput,
        owner_sig: &Base64VecU8,
        digest: impl Fn(&[u8; 32]) -> [u8; 32],
    ) -> [u8; 32] {
        let tier = note.tier;
        let pk: [u8; 32] = fixed(&note.pk.0).unwrap_or_else(|| env::panic_str("bad note encoding"));
        let nonce: [u8; 32] = fixed(&note.nonce.0).unwrap_or_else(|| env::panic_str("bad note encoding"));
        let sig: [u8; G1_LEN] = fixed(&note.sig.0).unwrap_or_else(|| env::panic_str("bad note encoding"));
        let t = v.tiers.get(usize::from(tier)).unwrap_or_else(|| env::panic_str("unknown tier"));
        let nf = note_nullifier(vault_id, tier, &pk, &nonce);
        require!(!self.nullifiers.contains(&nf), "note already spent");

        let owner_sig: [u8; 64] =
            fixed(&owner_sig.0).unwrap_or_else(|| env::panic_str("bad owner signature length"));
        require!(env::ed25519_verify(&owner_sig, digest(&nf), &pk), "bad owner signature");

        let mut message = [0u8; 65];
        message[0] = tier;
        message[1..33].copy_from_slice(&pk);
        message[33..].copy_from_slice(&nonce);
        let valid = decompress_g1(&sig).is_some_and(|sig_raw| {
            let h = hash_to_g1_raw(&message, &v.dst);
            pairing_ok(&sig_raw, &h, &t.pk_raw)
        });
        require!(valid, "invalid note");
        nf
    }

    fn exit(
        &mut self,
        vault_id: u32,
        note: NoteInput,
        owner_sig: Base64VecU8,
        to: AccountId,
        min_amount: u128,
        escape: bool,
    ) {
        let mut v = self.vault(vault_id);
        let nf = self.check_note(&v, vault_id, &note, &owner_sig, &to, min_amount);
        let tier = note.tier;
        let t = &v.tiers[usize::from(tier)];
        let shares = t.shares;
        require!(t.paid < t.issued, "more exits than notes issued");
        let amount = shares.saturating_mul(price(&v));
        require!(amount > EXIT_STORAGE_FEE, "note worth too little");
        let payout = amount - EXIT_STORAGE_FEE;
        require!(payout >= min_amount, "below the owner's minimum");
        require!(amount <= v.liquid, "not enough liquid funds in this vault");

        let mut h = self
            .holders
            .get(&to)
            .unwrap_or_else(|| env::panic_str("exits go only to an account that deposited"));
        require!(amount <= self.exit_limit(&h), "over this account's exit limit");
        let cap = v.hourly_cap;
        let window = if escape { &mut v.escape_window } else { &mut v.exit_window };
        use_window(window, cap, amount);

        self.nullifiers.insert(&nf);
        v.requests.retain(|r| r.nf != nf);
        track_full(&mut v);
        v.tiers[usize::from(tier)].paid += 1;
        v.total_shares -= shares;
        v.liquid -= amount;
        observe(&mut v);
        self.vaults.insert(&vault_id, &v);
        self.total_liquid -= amount;
        h.withdrawn = add(h.withdrawn, amount);
        let closed = amount.min(h.open);
        h.open -= closed;
        self.total_open -= closed;
        self.holders.insert(&to, &h);

        let _ = Promise::new(to.clone()).transfer(NearToken::from_yoctonear(payout)).then(
            Self::ext(env::current_account_id())
                .with_static_gas(CALLBACK_GAS)
                .on_exit_payout(to, U128(payout)),
        );
        self.require_solvent();
        event("exit", &format!("{{\"vault\":{vault_id},\"tier\":{tier}}}"));
    }
}

#[cfg(test)]
mod tests {
    use super::mul_div;

    #[test]
    fn mul_div_is_exact_beyond_128_bits() {
        assert_eq!(mul_div(6, 5, 10), 3);
        assert_eq!(mul_div(7, 0, 0), 0);
        let big = 1u128 << 100;
        assert_eq!(mul_div(big, big, big), big);
        assert_eq!(mul_div(u128::MAX, u128::MAX - 1, u128::MAX), u128::MAX - 1);
        assert_eq!(mul_div(u128::MAX, 3, 7), u128::MAX / 7 * 3 + (u128::MAX % 7) * 3 / 7);
    }
}
