//! `ona-mint`: blind-signature e-cash on NEAR. Draft, not audited. See `../SPEC.md`.
//!
//! The contract has no owner, no upgrade path and no callbacks. State is written before any
//! promise. Every token is verified on its own: aggregate verification is never used, because a
//! valid sum of signatures can be split into two invalid parts that still sum correctly.

use near_sdk::collections::LookupMap;
use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise};

pub const MAX_DENOMS: usize = 8;
/// Keeps the signer's `issue` budget (10 + 8 Tgas per token, 266 Tgas for 32) under 300 Tgas. The
/// 2026-11-10 sandbox run measured 222.5 Tgas for 32 tokens on the earlier code; not measured since.
pub const MAX_ISSUE: usize = 32;
/// Keeps the relay's `relay_claim` budget (10 + 10 Tgas per item, 290 Tgas for 28) under 300 Tgas.
/// About 8.3 Tgas per item was measured on the earlier code (264.6 Tgas for 32); 28 items not measured.
pub const MAX_CLAIM: usize = 28;
pub const MAX_CHANGE: usize = 8;
pub const ISSUE_TIMEOUT_NS: u64 = 3_600_000_000_000;
/// Value of `locked_until` once a record is locked. A lock no longer expires: only the signer's
/// `unlock` reopens a refund.
pub const LOCKED: u64 = u64::MAX;
/// Most record ids one `pending_deposits` call reads, live or not, so the view stays cheap.
pub const MAX_SCAN: u64 = 256;
/// Longest validity of an owner signature: its `expires_at` may be at most this far after the block
/// that executes it, so a signature cannot be made to last for ever.
pub const MAX_SIGNATURE_VALIDITY_NS: u64 = 7 * 24 * HOUR_NS;
/// Longest network name accepted by `new`.
pub const MAX_NETWORK_LEN: usize = 32;
const CALLBACK_GAS: Gas = Gas::from_tgas(15);
pub const HOUR_NS: u64 = 3_600_000_000_000;
pub const STORAGE_PER_TOKEN: u128 = 1_000_000_000_000_000_000_000;
pub const ISSUE_FEE_PER_TOKEN: u128 = 2_000_000_000_000_000_000_000;
pub const REDEEM_FEE: u128 = 10_000_000_000_000_000_000_000;
/// Enough for a transfer to create an implicit account (one key, about 182 bytes).
pub const MIN_PAYOUT: u128 = 10_000_000_000_000_000_000_000;

const G1_LEN: usize = 48;
const G2_LEN: usize = 96;

/// Base field modulus of BLS12-381, most significant limb first.
const P: [u64; 6] = [
    0x1a0111ea397fe69a,
    0x4b1ba7b6434bacd7,
    0x64774b84f38512bf,
    0x6730d2a0f6b0f624,
    0x1eabfffeb153ffff,
    0xb9feffffffffaaab,
];

/// G1 generator, uncompressed. Checked against `blst` in tests.
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

#[near(serializers = [json])]
#[derive(Clone)]
pub struct DenomInit {
    pub value: U128,
    /// Compressed G2 public key, 96 bytes.
    pub pk_g2: Base64VecU8,
    pub circulation_cap: u64,
    pub hourly_redeem_cap: u64,
}

#[near(serializers = [json])]
#[derive(Clone)]
pub struct TokenInput {
    pub denom_id: u8,
    pub pk: Base64VecU8,
    pub nonce: Base64VecU8,
    pub sig: Base64VecU8,
}

#[near(serializers = [json])]
#[derive(Clone)]
pub struct ClaimInput {
    pub token: TokenInput,
    pub owner_sig: Base64VecU8,
    /// Last block timestamp (ns) at which the owner signature is valid. Part of the signed digest.
    pub expires_at: U64,
}

#[near(serializers = [json])]
#[derive(Clone)]
pub struct BlindedOut {
    pub denom_id: u8,
    pub blinded: Base64VecU8,
}

#[near(serializers = [borsh])]
pub struct Denom {
    value: u128,
    pk_raw: Vec<u8>,
    circulation_cap: u64,
    hourly_redeem_cap: u64,
}

/// Sliding redemption limit (leaky bucket). Each redemption adds `HOUR_NS` to `level`, which drains
/// by `cap` per nanosecond, and a redemption is refused if `level` would pass `cap * HOUR_NS`.
/// So at most `cap` redemptions at once, and at most `cap + cap * t / 1 h` over any period `t`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Default)]
pub struct Bucket {
    pub level: U128,
    /// Block timestamp of the last accepted redemption.
    pub at: U64,
}

impl Bucket {
    /// Takes one unit if the bucket has room. Changes nothing on refusal.
    fn take(&mut self, cap: u64, now: u64) -> bool {
        let unit = u128::from(HOUR_NS);
        let full = u128::from(cap).saturating_mul(unit);
        let elapsed = u128::from(now.saturating_sub(self.at.0));
        let level = self.level.0.saturating_sub(elapsed.saturating_mul(u128::from(cap)));
        if level.saturating_add(unit) > full {
            return false;
        }
        self.level = U128(level + unit);
        self.at = U64(now);
        true
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Default)]
pub struct Counters {
    pub deposited: u64,
    /// Counted at `lock`, not at `issue`: once locked, a record's signatures may be public.
    pub issued: u64,
    pub redeemed: u64,
    pub refunded: u64,
    /// Limit shared by `redeem` and `spend`.
    pub bucket: Bucket,
    /// Separate limit for `relay_claim`, so holders emptying the public bucket cannot stop the relay.
    pub relay_bucket: Bucket,
}

#[near(serializers = [borsh])]
pub struct Pending {
    depositor: AccountId,
    items: Vec<(u8, [u8; G1_LEN])>,
    deadline: u64,
    /// Everything held for this record, returned in full by `refund`.
    total: u128,
    storage_paid: u128,
    is_change: bool,
    /// Zero until `lock`, then `LOCKED`. A signature is only ever published for a locked record.
    locked_until: u64,
}

#[near(serializers = [json])]
pub struct PendingPage {
    pub records: Vec<PendingView>,
    /// Where the next call should start. Moves forward even over a range with no live record.
    pub next: U64,
}

#[near(serializers = [json])]
pub struct PendingView {
    pub id: U64,
    pub depositor: AccountId,
    pub items: Vec<BlindedOut>,
    pub deadline: U64,
    pub locked_until: U64,
    pub total: U128,
    pub is_change: bool,
}

#[near(serializers = [json])]
pub struct DenomView {
    pub value: U128,
    pub pk_raw: Base64VecU8,
    pub circulation_cap: u64,
    pub hourly_redeem_cap: u64,
    pub counters: Counters,
}

#[near(serializers = [json])]
pub struct ConfigView {
    pub signer: AccountId,
    pub relay: AccountId,
    pub guardian: AccountId,
    pub network: String,
    pub denom_count: u8,
    pub halted: bool,
}

#[near(serializers = [json])]
pub struct ReserveStatus {
    pub balance: U128,
    pub storage_cost: U128,
    pub liabilities: U128,
    pub solvent: bool,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Mint {
    signer: AccountId,
    relay: AccountId,
    guardian: AccountId,
    network: String,
    dst: Vec<u8>,
    denom_count: u8,
    next_id: u64,
    halted: bool,
    signer_fees: u128,
    /// What live pending records hold beyond their own storage, which `storage_usage` already
    /// counts: `total - storage_paid`, summed.
    pending_total: u128,
    denoms: LookupMap<u8, Denom>,
    counters: LookupMap<u8, Counters>,
    pending: LookupMap<u64, Pending>,
    /// Spent tokens. The value says whether the relay collected it, which lets a relay that lost
    /// a transaction reply tell its own claim from a redemption by the owner.
    nullifiers: LookupMap<[u8; 32], bool>,
}

struct ParsedToken {
    denom_id: u8,
    pk: [u8; 32],
    nonce: [u8; 32],
    sig: [u8; G1_LEN],
}

fn sha256(data: &[u8]) -> [u8; 32] {
    env::sha256(data).try_into().unwrap_or_else(|_| env::panic_str("sha256 length"))
}

fn fixed<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

fn parse_token(t: &TokenInput) -> Option<ParsedToken> {
    Some(ParsedToken {
        denom_id: t.denom_id,
        pk: fixed(&t.pk.0)?,
        nonce: fixed(&t.nonce.0)?,
        sig: fixed(&t.sig.0)?,
    })
}

/// Compressed G1 form with the compression flag set and the infinity flag clear.
fn plausible_g1(p: &[u8; G1_LEN]) -> bool {
    p[0] & 0x80 != 0 && p[0] & 0x40 == 0
}

fn nullifier(denom_id: u8, pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut d = Vec::with_capacity(74);
    d.extend_from_slice(b"ONA-NF-V1");
    d.push(denom_id);
    d.extend_from_slice(pk);
    d.extend_from_slice(nonce);
    sha256(&d)
}

fn implicit_account(pk: &[u8; 32]) -> AccountId {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in pk {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s.parse().unwrap_or_else(|_| env::panic_str("implicit account"))
}

/// RFC 9380 `expand_message_xmd` with SHA-256, for 128 output bytes.
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

/// Reduces a 64-byte big-endian integer modulo p, bit by bit.
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

/// RFC 9380 hash to G1, uncompressed. Field elements are reduced, so the host cannot refuse them.
pub fn hash_to_g1_raw(msg: &[u8], dst: &[u8]) -> Vec<u8> {
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
    if !plausible_g1(p) {
        return None;
    }
    env::bls12381_p1_decompress(p).filter(|raw| raw.len() == 96)
}

/// `e(sig, -G2) * e(point, pk) == 1`. The host rejects points outside the subgroup.
fn pairing_ok(sig_raw: &[u8], point_raw: &[u8], pk_raw: &[u8]) -> bool {
    let mut input = Vec::with_capacity(576);
    input.extend_from_slice(sig_raw);
    input.extend_from_slice(&NEG_G2);
    input.extend_from_slice(point_raw);
    input.extend_from_slice(pk_raw);
    env::bls12381_pairing_check(&input).unwrap_or(false)
}

/// Mirrors `ona_token::redeem_digest_until`.
fn redeem_digest(contract: &AccountId, submitter: &AccountId, nf: &[u8; 32], expires_at: u64) -> [u8; 32] {
    let mut d = Vec::with_capacity(117);
    d.extend_from_slice(b"ONA-REDEEM-V2");
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(&sha256(submitter.as_bytes()));
    d.extend_from_slice(nf);
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// Mirrors `ona_token::spend_digest_until`. Tests sign with one and verify with the other.
#[allow(clippy::too_many_arguments)]
fn spend_digest(
    contract: &AccountId,
    submitter: &AccountId,
    denom_id: u8,
    nf: &[u8; 32],
    to: &AccountId,
    amount: u128,
    fee: u128,
    change: &[(u8, [u8; G1_LEN])],
    expires_at: u64,
) -> [u8; 32] {
    let mut d = Vec::with_capacity(180 + change.len() * 49);
    d.extend_from_slice(b"ONA-SPEND-V3");
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(&sha256(submitter.as_bytes()));
    d.push(denom_id);
    d.extend_from_slice(nf);
    d.extend_from_slice(&sha256(to.as_bytes()));
    d.extend_from_slice(&amount.to_le_bytes());
    d.extend_from_slice(&fee.to_le_bytes());
    d.extend_from_slice(&(change.len() as u32).to_le_bytes());
    for (denom, blinded) in change {
        d.push(*denom);
        d.extend_from_slice(blinded);
    }
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// Mirrors `ona_token::claim_digest_until`.
fn claim_digest(mint: &AccountId, relay: &AccountId, nf: &[u8; 32], expires_at: u64) -> [u8; 32] {
    let mut d = Vec::with_capacity(116);
    d.extend_from_slice(b"ONA-CLAIM-V2");
    d.extend_from_slice(&sha256(mint.as_bytes()));
    d.extend_from_slice(&sha256(relay.as_bytes()));
    d.extend_from_slice(nf);
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// The y coordinates (little-endian, sign bit cleared) of the eight small-order points of
/// edwards25519, including the non-canonical encodings p and p + 1 of 0 and 1. With such an owner
/// key, the non-strict `ed25519_verify` of the host can accept a trivial signature for any message.
/// Checked against `ed25519_dalek::VerifyingKey::is_weak` in tests.
const SMALL_ORDER_Y: [[u8; 32]; 7] = [
    [0; 32],
    {
        let mut y = [0u8; 32];
        y[0] = 1;
        y
    },
    hex32(b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    hex32(b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    hex32(b"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex32(b"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex32(b"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
];

const fn hex32(s: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// True for an owner key of small order, whatever its sign bit.
pub fn weak_owner_key(pk: &[u8; 32]) -> bool {
    let mut y = *pk;
    y[31] &= 0x7f;
    SMALL_ORDER_Y.contains(&y)
}

/// Checks an owner signature with its expiry. The host's `ed25519_verify` is not strict
/// (near-vm-runner 0.38.0 calls `verify`, not `verify_strict`), so small-order keys are refused here.
fn owner_sig_ok(sig: &[u8; 64], digest: [u8; 32], pk: &[u8; 32], expires_at: u64) -> Result<(), &'static str> {
    let now = env::block_timestamp();
    if now > expires_at {
        return Err("owner signature expired");
    }
    if expires_at > now.saturating_add(MAX_SIGNATURE_VALIDITY_NS) {
        return Err("owner signature expiry too far in the future");
    }
    if weak_owner_key(pk) {
        return Err("weak owner key");
    }
    if !env::ed25519_verify(sig, digest, pk) {
        return Err("bad owner signature");
    }
    Ok(())
}

/// Refuses the same blinded point twice in one record: both copies would get the same signature,
/// count twice in `issued`, and only one could ever be spent.
fn require_distinct(items: &[(u8, [u8; G1_LEN])]) {
    for (i, (_, p)) in items.iter().enumerate() {
        require!(!items[..i].iter().any(|(_, q)| q == p), "duplicate blinded point");
    }
}

/// Plain transfer without callback. If `to` was deleted in the meantime, NEAR returns the amount to
/// this contract, where nobody can take it out: solvency is unaffected, the payee loses it. Only
/// `spend` has a callback, because its payee is chosen by the token owner.
fn pay(to: AccountId, amount: u128) {
    if amount > 0 {
        let _ = Promise::new(to).transfer(NearToken::from_yoctonear(amount));
    }
}

fn event(name: &str, data: &str) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"ona-mint\",\"version\":\"1.0.0\",\"event\":\"{name}\",\"data\":{data}}}"
    ));
}

fn add(a: u128, b: u128) -> u128 {
    a.checked_add(b).unwrap_or_else(|| env::panic_str("amount overflow"))
}

fn mul(a: u128, b: u128) -> u128 {
    a.checked_mul(b).unwrap_or_else(|| env::panic_str("amount overflow"))
}

#[near]
impl Mint {
    #[init]
    pub fn new(
        denoms: Vec<DenomInit>,
        signer: AccountId,
        relay: AccountId,
        guardian: AccountId,
        network: String,
    ) -> Self {
        require!(!denoms.is_empty() && denoms.len() <= MAX_DENOMS, "bad denomination count");
        let contract = env::current_account_id();
        require!(
            signer != relay && signer != guardian && relay != guardian,
            "signer, relay and guardian must be distinct accounts"
        );
        require!(
            signer != contract && relay != contract && guardian != contract,
            "a role cannot be the mint itself"
        );
        require!(
            !network.is_empty()
                && network.len() <= MAX_NETWORK_LEN
                && network.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'),
            "network must be 1 to 32 characters among a-z, 0-9, - and _"
        );
        let dst = format!("ONA-MINT-V1:{network}:{contract}:BLS12381G1_XMD:SHA-256_SSWU_RO_");
        require!(dst.len() <= 255, "DST too long");

        let mut this = Self {
            signer,
            relay,
            guardian,
            network,
            dst: dst.into_bytes(),
            denom_count: denoms.len() as u8,
            next_id: 0,
            halted: false,
            signer_fees: 0,
            pending_total: 0,
            denoms: LookupMap::new(b"d".to_vec()),
            counters: LookupMap::new(b"c".to_vec()),
            pending: LookupMap::new(b"p".to_vec()),
            nullifiers: LookupMap::new(b"n".to_vec()),
        };

        // Tier safety rests on independent keys. Identical keys and a key with its negation are
        // refused here; other relations (k * pk for a known k) cannot be detected by the contract.
        require!(
            denoms.windows(2).all(|w| w[0].value.0 < w[1].value.0),
            "denomination values must strictly increase"
        );
        let mut seen: Vec<[u8; G2_LEN]> = Vec::new();
        for (id, d) in denoms.iter().enumerate() {
            require!(d.value.0 >= REDEEM_FEE + MIN_PAYOUT, "denomination too small");
            require!(d.circulation_cap > 0 && d.hourly_redeem_cap > 0, "caps must be positive");
            let pk: [u8; G2_LEN] =
                fixed(&d.pk_g2.0).unwrap_or_else(|| env::panic_str("bad key length"));
            require!(pk[0] & 0x80 != 0 && pk[0] & 0x40 == 0, "bad key flags");
            require!(!seen.iter().any(|k| k[..] == pk[..]), "duplicate key");
            let mut negated = pk;
            negated[0] ^= 0x20;
            require!(!seen.iter().any(|k| k[..] == negated[..]), "related key: the negation of another tier's key");
            seen.push(pk);
            let pk_raw = env::bls12381_p2_decompress(pk)
                .filter(|raw| raw.len() == 192)
                .unwrap_or_else(|| env::panic_str("bad key"));

            let mut check = Vec::with_capacity(576);
            check.extend_from_slice(&G1_GEN);
            check.extend_from_slice(&pk_raw);
            check.extend_from_slice(&NEG_G1);
            check.extend_from_slice(&pk_raw);
            require!(
                env::bls12381_pairing_check(&check).unwrap_or(false),
                "key outside the subgroup"
            );

            let id = id as u8;
            this.denoms.insert(
                &id,
                &Denom {
                    value: d.value.0,
                    pk_raw,
                    circulation_cap: d.circulation_cap,
                    hourly_redeem_cap: d.hourly_redeem_cap,
                },
            );
            this.counters.insert(&id, &Counters::default());
        }
        this
    }

    #[payable]
    pub fn deposit(&mut self, denom_id: u8, blinded: Vec<Base64VecU8>) -> U64 {
        require!(!self.halted, "halted");
        let n = blinded.len();
        require!(n.is_power_of_two() && n <= MAX_ISSUE, "token count must be a power of two up to 32");
        let denom = self.denom(denom_id);
        let items: Vec<(u8, [u8; G1_LEN])> = blinded
            .iter()
            .map(|b| {
                let p: [u8; G1_LEN] =
                    fixed(&b.0).unwrap_or_else(|| env::panic_str("bad blinded length"));
                require!(plausible_g1(&p), "bad blinded point");
                (denom_id, p)
            })
            .collect();
        require_distinct(&items);

        let mut c = self.counter(denom_id);
        self.require_room(&denom, &c, n as u64);
        c.deposited += n as u64;
        self.counters.insert(&denom_id, &c);

        let unit = add(add(denom.value, STORAGE_PER_TOKEN), ISSUE_FEE_PER_TOKEN);
        let base = mul(unit, n as u128);
        let depositor = env::predecessor_account_id();
        let id = self.store_pending(depositor.clone(), items, base, false);
        let total = self.pending.get(&id).map(|p| p.total).unwrap_or(0);

        let attached = env::attached_deposit().as_yoctonear();
        require!(attached >= total, "attached deposit too small");
        pay(depositor, attached - total);
        event("deposit", &format!("{{\"id\":{id},\"denom\":{denom_id},\"count\":{n}}}"));
        U64(id)
    }

    /// First half of issuance, and the accounting commitment. Blinded signatures are public as
    /// soon as an `issue` transaction is sent, even if it fails, so the tokens are counted as
    /// issued here and the record can no longer be refunded, unless the signer `unlock`s it. A
    /// signer that fails after publishing therefore costs the depositor, never other holders.
    pub fn lock(&mut self, deposit_id: U64) {
        require!(!self.halted, "halted");
        require!(env::predecessor_account_id() == self.signer, "only the signer can lock");
        let mut record =
            self.pending.get(&deposit_id.0).unwrap_or_else(|| env::panic_str("unknown deposit"));
        require!(record.locked_until == 0, "already locked");
        require!(env::block_timestamp() < record.deadline, "deadline passed");
        for (denom_id, _) in &record.items {
            let mut c = self.counter(*denom_id);
            c.issued += 1;
            self.counters.insert(denom_id, &c);
        }
        // The token values now back `issued`; only the issue fees stay held by the record.
        self.pending_total -= self.committed(&record.items);
        record.locked_until = LOCKED;
        self.pending.insert(&deposit_id.0, &record);
        event("lock", &format!("{{\"id\":{}}}", deposit_id.0));
    }

    /// Reverses a `lock`. The signer calls it only for a record whose signatures it never
    /// broadcast, for example a record it cannot sign. The record then refunds at its deadline.
    /// Refused if the tier has fewer live tokens than the record would remove.
    pub fn unlock(&mut self, deposit_id: U64) {
        require!(env::predecessor_account_id() == self.signer, "only the signer can unlock");
        let mut record =
            self.pending.get(&deposit_id.0).unwrap_or_else(|| env::panic_str("unknown deposit"));
        require!(record.locked_until != 0, "deposit is not locked");
        for (denom_id, _) in &record.items {
            let mut c = self.counter(*denom_id);
            require!(c.issued > c.redeemed, "tokens of this tier already redeemed");
            c.issued -= 1;
            self.counters.insert(denom_id, &c);
        }
        self.pending_total = add(self.pending_total, self.committed(&record.items));
        record.locked_until = 0;
        self.pending.insert(&deposit_id.0, &record);
        event("unlock", &format!("{{\"id\":{}}}", deposit_id.0));
    }

    /// Allowed at any time after `lock`, including after `halt`: the signatures may already be
    /// public. The event carries the blinded signatures, so a wallet can read them from any RPC
    /// that serves logs instead of looking for the transaction's arguments.
    pub fn issue(&mut self, deposit_id: U64, sigs: Vec<Base64VecU8>) {
        require!(env::predecessor_account_id() == self.signer, "only the signer can issue");
        let record =
            self.pending.get(&deposit_id.0).unwrap_or_else(|| env::panic_str("unknown deposit"));
        require!(record.locked_until != 0, "deposit is not locked");
        require!(sigs.len() == record.items.len(), "wrong signature count");

        for ((denom_id, blinded), sig) in record.items.iter().zip(sigs.iter()) {
            let denom = self.denom(*denom_id);
            let sig: [u8; G1_LEN] =
                fixed(&sig.0).unwrap_or_else(|| env::panic_str("bad signature length"));
            let sig_raw = decompress_g1(&sig).unwrap_or_else(|| env::panic_str("bad signature"));
            let blinded_raw =
                decompress_g1(blinded).unwrap_or_else(|| env::panic_str("bad blinded point"));
            require!(pairing_ok(&sig_raw, &blinded_raw, &denom.pk_raw), "bad signature");
        }

        self.pending.remove(&deposit_id.0);
        self.pending_total -= record.total - record.storage_paid - self.committed(&record.items);
        let fees = mul(ISSUE_FEE_PER_TOKEN, record.items.len() as u128);
        self.signer_fees = add(self.signer_fees, fees);
        // A change record's depositor may not exist yet, and this amount would be too small to
        // create it, so its storage refund goes to the signer instead of a failing transfer.
        if record.is_change {
            self.signer_fees = add(self.signer_fees, record.storage_paid);
        } else {
            pay(record.depositor, record.storage_paid);
        }
        let sigs_json = near_sdk::serde_json::to_string(&sigs)
            .unwrap_or_else(|_| env::panic_str("signature encoding"));
        event(
            "issue",
            &format!("{{\"id\":{},\"count\":{},\"sigs\":{sigs_json}}}", deposit_id.0, sigs.len()),
        );
    }

    /// Only for a record that is not locked, after its deadline.
    pub fn refund(&mut self, deposit_id: U64) {
        let record =
            self.pending.get(&deposit_id.0).unwrap_or_else(|| env::panic_str("unknown deposit"));
        require!(record.locked_until == 0, "deposit is locked: only the signer can unlock it");
        require!(env::block_timestamp() >= record.deadline, "deadline not reached");
        for (denom_id, _) in &record.items {
            let mut c = self.counter(*denom_id);
            c.refunded += 1;
            self.counters.insert(denom_id, &c);
        }
        self.pending.remove(&deposit_id.0);
        self.pending_total -= record.total - record.storage_paid;
        pay(record.depositor, record.total);
        event("refund", &format!("{{\"id\":{}}}", deposit_id.0));
    }

    /// Pays the token's own implicit account. Needs the owner's signature naming the submitter,
    /// so that nobody who merely saw the token can force its exit and collect the fee.
    pub fn redeem(&mut self, token: TokenInput, owner_sig: Base64VecU8, expires_at: U64) {
        let t = parse_token(&token).unwrap_or_else(|| env::panic_str("bad token encoding"));
        let denom = self.denom(t.denom_id);
        let nf = nullifier(t.denom_id, &t.pk, &t.nonce);
        require!(!self.nullifiers.contains_key(&nf), "token already spent");
        let sig: [u8; 64] =
            fixed(&owner_sig.0).unwrap_or_else(|| env::panic_str("bad owner signature length"));
        let digest = redeem_digest(
            &env::current_account_id(),
            &env::predecessor_account_id(),
            &nf,
            expires_at.0,
        );
        if let Err(reason) = owner_sig_ok(&sig, digest, &t.pk, expires_at.0) {
            env::panic_str(reason);
        }
        require!(self.token_valid(&t, &denom), "invalid token");
        if let Err(reason) = self.mark_spent(&nf, t.denom_id, &denom, false) {
            env::panic_str(reason);
        }
        pay(implicit_account(&t.pk), denom.value - REDEEM_FEE);
        pay(env::predecessor_account_id(), REDEEM_FEE);
        event("redeem", &format!("{{\"denom\":{}}}", t.denom_id));
    }

    /// Pays `to` directly and queues blinded change. Authorized by the token's own key, so the
    /// submitting account learns nothing about the owner and cannot alter any field.
    #[allow(clippy::too_many_arguments)]
    pub fn spend(
        &mut self,
        token: TokenInput,
        owner_sig: Base64VecU8,
        to: AccountId,
        amount: U128,
        fee: U128,
        change: Vec<BlindedOut>,
        expires_at: U64,
    ) {
        let t = parse_token(&token).unwrap_or_else(|| env::panic_str("bad token encoding"));
        let denom = self.denom(t.denom_id);
        let nf = nullifier(t.denom_id, &t.pk, &t.nonce);
        require!(!self.nullifiers.contains_key(&nf), "token already spent");
        require!(change.len() <= MAX_CHANGE, "too many change tokens");
        // Change requested after a halt could never be issued, only refunded in the clear.
        require!(!self.halted || change.is_empty(), "no change while halted");
        require!(to != env::current_account_id(), "cannot pay the mint");
        require!(amount.0 >= MIN_PAYOUT, "amount too small");

        let mut items: Vec<(u8, [u8; G1_LEN])> = Vec::with_capacity(change.len());
        let mut change_value = 0u128;
        for out in &change {
            let d = self.denom(out.denom_id);
            let p: [u8; G1_LEN] =
                fixed(&out.blinded.0).unwrap_or_else(|| env::panic_str("bad blinded length"));
            require!(plausible_g1(&p), "bad blinded point");
            change_value = add(change_value, d.value);
            items.push((out.denom_id, p));
        }
        require_distinct(&items);

        let sig: [u8; 64] =
            fixed(&owner_sig.0).unwrap_or_else(|| env::panic_str("bad owner signature length"));
        let contract = env::current_account_id();
        let submitter = env::predecessor_account_id();
        let digest = spend_digest(
            &contract,
            &submitter,
            t.denom_id,
            &nf,
            &to,
            amount.0,
            fee.0,
            &items,
            expires_at.0,
        );
        if let Err(reason) = owner_sig_ok(&sig, digest, &t.pk, expires_at.0) {
            env::panic_str(reason);
        }
        require!(self.token_valid(&t, &denom), "invalid token");
        require!(
            add(add(amount.0, fee.0), change_value) == denom.value,
            "amount, fee and change must equal the token value"
        );

        if let Err(reason) = self.mark_spent(&nf, t.denom_id, &denom, false) {
            env::panic_str(reason);
        }

        let mut change_cost = 0u128;
        if !items.is_empty() {
            let n = items.len() as u128;
            let held = add(STORAGE_PER_TOKEN, ISSUE_FEE_PER_TOKEN);
            let base = add(change_value, mul(held, n));
            for (denom_id, _) in &items {
                let d = self.denom(*denom_id);
                let mut c = self.counter(*denom_id);
                self.require_room(&d, &c, 1);
                c.deposited += 1;
                self.counters.insert(denom_id, &c);
            }
            let id = self.store_pending(implicit_account(&t.pk), items, base, true);
            let total = self.pending.get(&id).map(|p| p.total).unwrap_or(0);
            change_cost = total - change_value;
            event("change", &format!("{{\"id\":{id}}}"));
        }
        require!(fee.0 >= change_cost, "fee does not cover the change");

        // A transfer to a missing account fails after the nullifier is written, and the money
        // returns here. The callback sends it to the token's own implicit account.
        let _ = Promise::new(to).transfer(NearToken::from_yoctonear(amount.0)).then(
            Self::ext(contract)
                .with_static_gas(CALLBACK_GAS)
                .on_spend_payout(implicit_account(&t.pk), amount),
        );
        pay(submitter, fee.0 - change_cost);
        event("spend", &format!("{{\"denom\":{}}}", t.denom_id));
    }

    #[private]
    pub fn on_spend_payout(&mut self, owner: AccountId, amount: U128) {
        if env::promise_result_checked(0, 16).is_err() {
            pay(owner, amount.0);
            event("spend_returned", "{}");
        }
    }

    /// Bad items return `false` and the batch continues, so one bad token cannot block the rest.
    pub fn relay_claim(&mut self, items: Vec<ClaimInput>) -> Vec<bool> {
        require!(env::predecessor_account_id() == self.relay, "only the relay can claim");
        require!(items.len() <= MAX_CLAIM, "too many items");
        let mut total = 0u128;
        let results: Vec<bool> = items
            .iter()
            .map(|item| match self.try_claim(item) {
                Some(value) => {
                    total = add(total, value);
                    true
                }
                None => false,
            })
            .collect();
        pay(self.relay.clone(), total);
        let ok = results.iter().filter(|r| **r).count();
        event("relay_claim", &format!("{{\"ok\":{ok},\"count\":{}}}", results.len()));
        results
    }

    /// Permanent. Stops new money only: `deposit`, `lock` and change in `spend`. It does not stop
    /// `redeem`, `spend` without change, `relay_claim`, `refund`, `unlock`, or `issue` of a record
    /// already locked, and it does not lower the redemption limits: a thief holding the signer key
    /// keeps redeeming at the limit's pace after a halt.
    pub fn halt(&mut self) {
        require!(env::predecessor_account_id() == self.guardian, "only the guardian can halt");
        self.halted = true;
        event("halt", "{}");
    }

    pub fn claim_signer_fees(&mut self) {
        require!(env::predecessor_account_id() == self.signer, "only the signer can claim");
        let amount = core::mem::take(&mut self.signer_fees);
        pay(self.signer.clone(), amount);
    }

    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            signer: self.signer.clone(),
            relay: self.relay.clone(),
            guardian: self.guardian.clone(),
            network: self.network.clone(),
            denom_count: self.denom_count,
            halted: self.halted,
        }
    }

    pub fn get_denom(&self, denom_id: u8) -> DenomView {
        let d = self.denom(denom_id);
        DenomView {
            value: U128(d.value),
            pk_raw: Base64VecU8(d.pk_raw),
            circulation_cap: d.circulation_cap,
            hourly_redeem_cap: d.hourly_redeem_cap,
            counters: self.counter(denom_id),
        }
    }

    pub fn is_spent(&self, nf: Base64VecU8) -> bool {
        fixed::<32>(&nf.0).is_some_and(|nf| self.nullifiers.contains_key(&nf))
    }

    pub fn spent_by_relay(&self, nf: Base64VecU8) -> bool {
        fixed::<32>(&nf.0).is_some_and(|nf| self.nullifiers.get(&nf).unwrap_or(false))
    }

    /// Live records from `from`, reading at most `MAX_SCAN` ids. An empty answer does not mean
    /// that no record follows: use `pending_scan` to learn where to continue.
    pub fn pending_deposits(&self, from: U64, limit: u16) -> Vec<PendingView> {
        self.pending_scan(from, limit).records
    }

    /// Like `pending_deposits`, plus the id to start the next call from. A `limit` of 0 counts as 1,
    /// so `next` always moves forward while records remain.
    pub fn pending_scan(&self, from: U64, limit: u16) -> PendingPage {
        let limit = usize::from(limit.clamp(1, 64));
        let end = from.0.saturating_add(MAX_SCAN).min(self.next_id);
        let mut records = Vec::new();
        let mut next = end.max(from.0);
        for id in from.0..end {
            if records.len() == limit {
                next = id;
                break;
            }
            if let Some(p) = self.pending.get(&id) {
                records.push(PendingView {
                    id: U64(id),
                    depositor: p.depositor,
                    items: p
                        .items
                        .iter()
                        .map(|(denom_id, b)| BlindedOut {
                            denom_id: *denom_id,
                            blinded: Base64VecU8(b.to_vec()),
                        })
                        .collect(),
                    deadline: U64(p.deadline),
                    locked_until: U64(p.locked_until),
                    total: U128(p.total),
                    is_change: p.is_change,
                });
            }
        }
        PendingPage { records, next: U64(next) }
    }

    /// Invariant I1: the balance covers storage and every claim on the contract.
    pub fn reserve_status(&self) -> ReserveStatus {
        let mut liabilities = add(self.pending_total, self.signer_fees);
        for id in 0..self.denom_count {
            let d = self.denom(id);
            let c = self.counter(id);
            let live = u128::from(c.issued - c.redeemed);
            liabilities = add(liabilities, mul(live, add(d.value, STORAGE_PER_TOKEN)));
        }
        let storage_cost = mul(
            u128::from(env::storage_usage()),
            env::storage_byte_cost().as_yoctonear(),
        );
        let balance = env::account_balance().as_yoctonear();
        ReserveStatus {
            balance: U128(balance),
            storage_cost: U128(storage_cost),
            liabilities: U128(liabilities),
            solvent: balance >= add(storage_cost, liabilities),
        }
    }
}

impl Mint {
    fn denom(&self, id: u8) -> Denom {
        self.denoms.get(&id).unwrap_or_else(|| env::panic_str("unknown denomination"))
    }

    fn counter(&self, id: u8) -> Counters {
        self.counters.get(&id).unwrap_or_else(|| env::panic_str("unknown denomination"))
    }

    /// What a record's tokens are worth once counted in `issued`: value plus the token's storage,
    /// the same amount `reserve_status` counts per live token.
    fn committed(&self, items: &[(u8, [u8; G1_LEN])]) -> u128 {
        items.iter().fold(0u128, |acc, (denom_id, _)| {
            add(acc, add(self.denom(*denom_id).value, STORAGE_PER_TOKEN))
        })
    }

    fn require_room(&self, denom: &Denom, c: &Counters, n: u64) {
        let outstanding = c.deposited - c.refunded - c.redeemed;
        require!(outstanding + n <= denom.circulation_cap, "circulation cap reached");
    }

    /// Writes a pending record, charging its measured storage on top of `base`. Returns its id.
    fn store_pending(
        &mut self,
        depositor: AccountId,
        items: Vec<(u8, [u8; G1_LEN])>,
        base: u128,
        is_change: bool,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let before = env::storage_usage();
        let mut record = Pending {
            depositor,
            items,
            deadline: env::block_timestamp() + ISSUE_TIMEOUT_NS,
            total: base,
            storage_paid: 0,
            is_change,
            locked_until: 0,
        };
        self.pending.insert(&id, &record);
        let bytes = u128::from(env::storage_usage() - before);
        record.storage_paid = mul(bytes, env::storage_byte_cost().as_yoctonear());
        record.total = add(base, record.storage_paid);
        self.pending.insert(&id, &record);
        self.pending_total = add(self.pending_total, base);
        id
    }

    fn token_valid(&self, t: &ParsedToken, denom: &Denom) -> bool {
        let Some(sig_raw) = decompress_g1(&t.sig) else {
            return false;
        };
        let mut message = [0u8; 65];
        message[0] = t.denom_id;
        message[1..33].copy_from_slice(&t.pk);
        message[33..].copy_from_slice(&t.nonce);
        let h = hash_to_g1_raw(&message, &self.dst);
        pairing_ok(&sig_raw, &h, &denom.pk_raw)
    }

    /// Applies the redemption limits and records the nullifier. Writes nothing on refusal.
    fn mark_spent(
        &mut self,
        nf: &[u8; 32],
        denom_id: u8,
        denom: &Denom,
        by_relay: bool,
    ) -> Result<(), &'static str> {
        let mut c = self.counter(denom_id);
        if c.redeemed + 1 > c.issued {
            return Err("more redemptions than issued tokens");
        }
        let now = env::block_timestamp();
        let bucket = if by_relay { &mut c.relay_bucket } else { &mut c.bucket };
        if !bucket.take(denom.hourly_redeem_cap, now) {
            return Err("hourly redemption limit reached");
        }
        c.redeemed += 1;
        self.counters.insert(&denom_id, &c);
        self.nullifiers.insert(nf, &by_relay);
        Ok(())
    }

    /// One `relay_claim` item. Returns the value collected, or `None` to skip the item.
    fn try_claim(&mut self, item: &ClaimInput) -> Option<u128> {
        let t = parse_token(&item.token)?;
        let denom = self.denoms.get(&t.denom_id)?;
        let sig: [u8; 64] = fixed(&item.owner_sig.0)?;
        let nf = nullifier(t.denom_id, &t.pk, &t.nonce);
        if self.nullifiers.contains_key(&nf) {
            return None;
        }
        // The cheap check first: a wrong owner signature should not cost a pairing.
        let digest = claim_digest(&env::current_account_id(), &self.relay, &nf, item.expires_at.0);
        if owner_sig_ok(&sig, digest, &t.pk, item.expires_at.0).is_err()
            || !self.token_valid(&t, &denom)
        {
            return None;
        }
        self.mark_spent(&nf, t.denom_id, &denom, true).ok()?;
        Some(denom.value)
    }
}
