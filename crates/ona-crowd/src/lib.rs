//! Crowd simulator for the ONA pool demo.
//!
//! At launch the pool is empty, so a real user has no one to hide among. This creates fake users from
//! a seed, gives each a behaviour (when they deposit, which notes, which vault, how long they stay,
//! full or partial exit) and runs the agent rules of the pool over them.
//!
//! Exits go back only to the account that deposited. How
//! much each account puts in and takes out is public. What stays private is which vault each user
//! chose and when the agent placed for them. The outputs are:
//! - the public timeline: only what the chain shows (deposits on the mint, the agent's placements and
//!   withdrawals, exit payments), with no link between a user and a vault;
//! - the ground truth, kept apart, which holds that link so the privacy can be measured.
//!
//! The simulation models no yield: what is placed comes back unchanged, so an account's exits are
//! capped by its deposits. Times are seconds from the start of the run, amounts are whole units of
//! the asset.

pub mod chain;
mod measure;
pub mod near;
pub mod parades;

pub use measure::{candidates, guesses, privacy, Candidates, Guesses, Privacy, Sizes};

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// The most tokens one mint deposit can carry. Counts must also be powers of two.
pub const MAX_NOTES_PER_DEPOSIT: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultKind {
    Lending,
    Staking,
}

/// A vault a request can name: its type and the contract that runs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    pub kind: VaultKind,
    pub contract: String,
}

/// The agent's rules, from the pool architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentRules {
    /// The agent's public account, which places, withdraws and pays.
    pub account: String,
    /// Requests waiting in a vault before the agent places or withdraws a batch. At least 2.
    pub k: usize,
    /// Least time between a request and its placement.
    pub min_wait_secs: u64,
    /// Least time between a request and any exit payment for it.
    pub min_stay_secs: u64,
    /// A batch runs at a random moment within this many seconds once it is allowed.
    pub window_secs: u64,
    /// Each exit payment is sent at a random moment within this many seconds after the withdrawal.
    pub exit_window_secs: u64,
    /// Countermeasure, 0 = off: share of the funds the agent keeps liquid. Exits are paid from this
    /// reserve, so a vault withdrawal no longer precedes a precise exit.
    pub reserve_percent: u8,
    /// Countermeasure, 0 = off: the agent moves funds between the reserve and the vaults only at
    /// multiples of this period, and only the net difference per vault.
    pub settlement_period_secs: u64,
    /// Countermeasure, 0 = off: average number per hour of one-note round trips between two vaults,
    /// unrelated to any request. Each costs four agent transactions.
    pub noise_moves_per_hour: u32,
    /// With net settlement, 0 = off: a settlement runs only once at least this many requests were
    /// placed or left since the last one; otherwise it waits for the next period.
    pub min_active_per_settlement: usize,
}

impl AgentRules {
    /// True when placements follow request batches and exits follow vault withdrawals one to one.
    pub fn direct_placement(&self) -> bool {
        self.settlement_period_secs == 0
    }

    pub fn direct_exit(&self) -> bool {
        self.direct_placement() && self.reserve_percent == 0
    }
}

impl Default for AgentRules {
    fn default() -> Self {
        Self {
            account: "agent.example.testnet".into(),
            k: 5,
            min_wait_secs: 300,
            min_stay_secs: 900,
            window_secs: 300,
            exit_window_secs: 300,
            reserve_percent: 0,
            settlement_period_secs: 0,
            noise_moves_per_hour: 0,
            min_active_per_settlement: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub seed: u64,
    pub users: usize,
    /// Fixed note values, in units of the asset.
    pub denominations: Vec<u64>,
    /// Vaults a request can name. Required: there is no default list.
    pub vaults: Vec<Vault>,
    /// Allowed note counts per denomination in one deposit. Powers of two, as the mint requires.
    pub notes_per_denomination: Vec<u32>,
    pub mint_account: String,
    /// Deposits happen at a random moment in `[0, deposit_window_secs)`.
    pub deposit_window_secs: u64,
    /// A user sends a request at most this long after the deposit.
    pub request_delay_max_secs: u64,
    /// How long a user wants to stay, drawn in this range, counted from the request.
    pub stay_min_secs: u64,
    pub stay_max_secs: u64,
    /// Chance, in percent, that a user takes out only part of the notes.
    pub partial_exit_percent: u8,
    /// The agent acts until this time. Requests still waiting then are left as they are.
    pub run_secs: u64,
    pub agent: AgentRules,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            seed: 1,
            users: 50,
            denominations: vec![1, 10, 100],
            vaults: Vec::new(),
            notes_per_denomination: vec![1, 2, 4],
            mint_account: "mint.example.testnet".into(),
            deposit_window_secs: 1800,
            request_delay_max_secs: 120,
            stay_min_secs: 900,
            stay_max_secs: 3600,
            partial_exit_percent: 30,
            run_secs: 3 * 3600,
            agent: AgentRules::default(),
        }
    }
}

fn valid_account(id: &str) -> bool {
    (2..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !id.starts_with(['.', '_', '-'])
        && !id.ends_with(['.', '_', '-'])
}

impl Config {
    pub fn check(&self) -> Result<()> {
        if self.users == 0 {
            bail!("at least one user is required");
        }
        if self.denominations.is_empty() || self.denominations.contains(&0) {
            bail!("denominations must be positive and at least one is required");
        }
        for (i, d) in self.denominations.iter().enumerate() {
            if self.denominations[..i].contains(d) {
                bail!("denomination {d} is listed twice");
            }
        }
        if self.vaults.is_empty() {
            bail!("a list of vaults is required");
        }
        for v in &self.vaults {
            if !valid_account(&v.contract) {
                bail!("vault contract {:?} is not a NEAR account id", v.contract);
            }
        }
        for account in [&self.mint_account, &self.agent.account] {
            if !valid_account(account) {
                bail!("{account:?} is not a NEAR account id");
            }
        }
        if self.notes_per_denomination.is_empty()
            || self.notes_per_denomination.iter().any(|&n| !n.is_power_of_two() || n > MAX_NOTES_PER_DEPOSIT)
        {
            bail!("note counts must be powers of two up to {MAX_NOTES_PER_DEPOSIT}");
        }
        if self.agent.k < 2 {
            bail!("k must be at least 2, so that every batch mixes several requests");
        }
        if self.deposit_window_secs == 0 || self.agent.window_secs == 0 || self.agent.exit_window_secs == 0 {
            bail!("windows must be positive");
        }
        if self.stay_min_secs > self.stay_max_secs {
            bail!("stay_min_secs is above stay_max_secs");
        }
        if self.partial_exit_percent > 100 {
            bail!("partial_exit_percent is above 100");
        }
        if self.run_secs < self.deposit_window_secs {
            bail!("run_secs must cover the deposit window");
        }
        if self.agent.reserve_percent > 90 {
            bail!("reserve_percent must be at most 90");
        }
        if self.agent.noise_moves_per_hour > 3600 {
            bail!("noise_moves_per_hour must be at most 3600");
        }
        if self.agent.noise_moves_per_hour > 0 && self.vaults.len() < 2 {
            bail!("noise needs at least two vaults");
        }
        Ok(())
    }
}

/// A fake user: the key of its implicit NEAR account, which both deposits and receives the exits.
/// `Debug` shows the account only.
pub struct FakeUser {
    pub index: usize,
    pub key: SigningKey,
}

pub fn implicit_account(key: &SigningKey) -> String {
    key.verifying_key().as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

impl FakeUser {
    pub fn account(&self) -> String {
        implicit_account(&self.key)
    }
}

impl fmt::Debug for FakeUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeUser").field("index", &self.index).field("account", &self.account()).finish()
    }
}

/// Notes of one denomination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notes {
    pub denomination: u64,
    pub count: u32,
}

/// One user's behaviour. Part of the ground truth, never of the public timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub deposit_at: u64,
    pub notes: Vec<Notes>,
    pub request_at: u64,
    pub vault: usize,
    pub exit_at: u64,
    pub exit_notes: Vec<Notes>,
}

impl Profile {
    pub fn is_partial(&self) -> bool {
        total_notes(&self.exit_notes) < total_notes(&self.notes)
    }
}

fn total_notes(notes: &[Notes]) -> u32 {
    notes.iter().map(|n| n.count).sum()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Deposit,
    Placement,
    Withdrawal,
    ExitPayment,
}

/// What the chain shows. Nothing here names a request or links a user to a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEvent {
    pub id: usize,
    pub at_secs: u64,
    pub kind: EventKind,
    pub from: String,
    pub to: String,
    pub denomination: u64,
    pub count: u32,
    pub amount: u64,
}

/// What links one user to the public events. Kept apart from the timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTruth {
    pub user: usize,
    pub account: String,
    pub vault: String,
    pub profile: Profile,
    pub placed_at: Option<u64>,
    pub withdrawn_at: Option<u64>,
    pub deposit_events: Vec<usize>,
    /// Batches shared with other requests.
    pub placement_events: Vec<usize>,
    pub withdrawal_events: Vec<usize>,
    pub payment_events: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Truth {
    pub requests: Vec<RequestTruth>,
}

pub struct Simulation {
    pub users: Vec<FakeUser>,
    pub timeline: Vec<PublicEvent>,
    pub truth: Truth,
}

fn draw_key(rng: &mut ChaCha20Rng) -> SigningKey {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn draw_profile(config: &Config, rng: &mut ChaCha20Rng) -> Profile {
    let deposit_at = rng.gen_range(0..config.deposit_window_secs);
    // Each denomination is used with even odds; at least one is always kept.
    let mut notes: Vec<Notes> = Vec::new();
    for &denomination in &config.denominations {
        if rng.gen_bool(0.5) {
            let count = config.notes_per_denomination[rng.gen_range(0..config.notes_per_denomination.len())];
            notes.push(Notes { denomination, count });
        }
    }
    if notes.is_empty() {
        let denomination = config.denominations[rng.gen_range(0..config.denominations.len())];
        let count = config.notes_per_denomination[rng.gen_range(0..config.notes_per_denomination.len())];
        notes.push(Notes { denomination, count });
    }
    let request_at = deposit_at + rng.gen_range(0..=config.request_delay_max_secs);
    let vault = rng.gen_range(0..config.vaults.len());
    let exit_at = request_at + rng.gen_range(config.stay_min_secs..=config.stay_max_secs);

    let total = total_notes(&notes);
    let partial = total > 1 && rng.gen_range(0..100u8) < config.partial_exit_percent;
    let exit_notes = if partial {
        // Keep between 1 and total - 1 notes out, taken from the denominations in order.
        let mut left = rng.gen_range(1..total);
        let mut out = Vec::new();
        for n in &notes {
            let take = n.count.min(left);
            if take > 0 {
                out.push(Notes { denomination: n.denomination, count: take });
                left -= take;
            }
        }
        out
    } else {
        notes.clone()
    };
    Profile { deposit_at, notes, request_at, vault, exit_at, exit_notes }
}

struct Pending {
    at: u64,
    kind: EventKind,
    from: String,
    to: String,
    denomination: u64,
    count: u32,
}

struct State {
    placed_at: Option<u64>,
    withdrawn_at: Option<u64>,
    deposits: Vec<usize>,
    placements: Vec<usize>,
    withdrawals: Vec<usize>,
    payments: Vec<usize>,
}

/// Adds one event per denomination of a batch, summing the notes of its requests.
fn batch_events(
    events: &mut Vec<Pending>,
    at: u64,
    kind: EventKind,
    from: &str,
    to: &str,
    notes: impl Iterator<Item = Notes>,
) -> Vec<usize> {
    let mut sums: BTreeMap<u64, u32> = BTreeMap::new();
    for n in notes {
        *sums.entry(n.denomination).or_default() += n.count;
    }
    sums.into_iter()
        .map(|(denomination, count)| {
            events.push(Pending { at, kind, from: from.into(), to: to.into(), denomination, count });
            events.len() - 1
        })
        .collect()
}

fn notes_amount(notes: &[Notes]) -> u64 {
    notes.iter().map(|n| n.denomination * u64::from(n.count)).sum()
}

/// An exit payment waiting for the reserve.
struct QueuedPayment {
    due: u64,
    seq: usize,
    user: usize,
    denomination: u64,
}

/// One note lent by noise from vault `from` to vault `to`, to be moved back.
struct NoiseReturn {
    due: u64,
    from: usize,
    to: usize,
    denomination: u64,
}

/// What the agent really holds: liquid funds and each vault's balance.
struct Funds {
    liquid: u64,
    /// Liquid funds of requests not placed yet, which exits may not use.
    earmarked: u64,
    vaults: Vec<u64>,
    /// Notes noise has moved into (positive) or out of (negative) each vault and not moved back.
    offsets: Vec<i64>,
    smallest: u64,
    descending: Vec<u64>,
}

impl Funds {
    fn new(config: &Config) -> Self {
        let mut descending = config.denominations.clone();
        descending.sort_unstable_by(|a, b| b.cmp(a));
        Self {
            liquid: 0,
            earmarked: 0,
            vaults: vec![0; config.vaults.len()],
            offsets: vec![0; config.vaults.len()],
            smallest: *descending.last().expect("checked: at least one denomination"),
            descending,
        }
    }

    fn available(&self) -> u64 {
        self.liquid - self.earmarked
    }

    fn move_in(&mut self, vault: usize, amount: u64) {
        self.liquid -= amount;
        self.vaults[vault] += amount;
    }

    fn move_out(&mut self, vault: usize, amount: u64) {
        self.vaults[vault] -= amount;
        self.liquid += amount;
    }

    /// Notes for `amount`, largest first. What cannot be cut is left out.
    fn cut(&self, mut amount: u64) -> Vec<Notes> {
        let mut out = Vec::new();
        for &d in &self.descending {
            let count = amount / d;
            if count > 0 {
                out.push(Notes { denomination: d, count: count as u32 });
                amount -= count * d;
            }
        }
        out
    }

    /// The largest amount up to `amount` that whole notes can make.
    fn cut_down(&self, amount: u64) -> u64 {
        notes_amount(&self.cut(amount))
    }

    fn round_up(&self, amount: u64) -> u64 {
        amount.div_ceil(self.smallest) * self.smallest
    }

    fn emit(&self, events: &mut Vec<Pending>, at: u64, kind: EventKind, from: &str, to: &str, amount: u64) -> Vec<usize> {
        batch_events(events, at, kind, from, to, self.cut(amount).into_iter())
    }
}

/// Runs the whole simulation from `config.seed`. The same configuration always gives the same
/// result, so anyone who knows the seed can rebuild every key and the ground truth: use it for
/// demos and tests only, never on a real chain.
pub fn simulate(config: &Config) -> Result<Simulation> {
    simulate_with(config, ChaCha20Rng::seed_from_u64(config.seed))
}

/// Runs the simulation from a secret 32-byte seed, ignoring `config.seed`. For a real chain, the
/// seed must come from the system's randomness and never be stored: it determines every key and the
/// vault each user chose.
pub fn simulate_secret(config: &Config, seed: [u8; 32]) -> Result<Simulation> {
    simulate_with(config, ChaCha20Rng::from_seed(seed))
}

fn simulate_with(config: &Config, mut rng: ChaCha20Rng) -> Result<Simulation> {
    config.check()?;
    let mut users = Vec::with_capacity(config.users);
    let mut profiles = Vec::with_capacity(config.users);
    for index in 0..config.users {
        let key = draw_key(&mut rng);
        users.push(FakeUser { index, key });
        profiles.push(draw_profile(config, &mut rng));
    }

    let mut events: Vec<Pending> = Vec::new();
    let mut states: Vec<State> = profiles
        .iter()
        .zip(&users)
        .map(|(p, u)| {
            let deposits = p
                .notes
                .iter()
                .map(|n| {
                    events.push(Pending {
                        at: p.deposit_at,
                        kind: EventKind::Deposit,
                        from: u.account(),
                        to: config.mint_account.clone(),
                        denomination: n.denomination,
                        count: n.count,
                    });
                    events.len() - 1
                })
                .collect();
            State {
                placed_at: None,
                withdrawn_at: None,
                deposits,
                placements: Vec::new(),
                withdrawals: Vec::new(),
                payments: Vec::new(),
            }
        })
        .collect();

    let rules = &config.agent;
    let vault_count = config.vaults.len();
    let mut place_at: Vec<Option<u64>> = vec![None; vault_count];
    let mut withdraw_at: Vec<Option<u64>> = vec![None; vault_count];
    // What the agent really holds, as opposed to what each vault owes its requests (`owed`). They
    // differ only with countermeasures.
    let mut funds = Funds::new(config);
    let mut owed: Vec<u64> = vec![0; vault_count];
    let mut queue: Vec<QueuedPayment> = Vec::new();
    let mut returns: Vec<NoiseReturn> = Vec::new();
    let mut seq = 0usize;
    let mut active_since_settlement = 0usize;
    let last_tick = config.run_secs + 4 * rules.settlement_period_secs.max(3600) + rules.exit_window_secs;
    let mut t = 0;
    loop {
        if t > config.run_secs && ((queue.is_empty() && returns.is_empty()) || t > last_tick) {
            break;
        }
        for p in profiles.iter().filter(|p| p.request_at == t) {
            // The request spends the user's notes towards the pool. Until placed, they are set aside.
            funds.liquid += notes_amount(&p.notes);
            if rules.direct_placement() {
                funds.earmarked += notes_amount(&p.notes);
            }
        }
        let acting = t <= config.run_secs;
        for (v, vault) in config.vaults.iter().enumerate().filter(|_| acting) {
            let in_vault = |i: &usize| profiles[*i].vault == v;
            let placeable: Vec<usize> = (0..users.len())
                .filter(in_vault)
                .filter(|&i| states[i].placed_at.is_none() && profiles[i].request_at + rules.min_wait_secs <= t)
                .collect();
            if place_at[v].is_none() && placeable.len() >= rules.k {
                place_at[v] = Some(t + rng.gen_range(0..rules.window_secs));
            }
            if place_at[v] == Some(t) {
                place_at[v] = None;
                let total: u64 = placeable.iter().map(|&i| notes_amount(&profiles[i].notes)).sum();
                owed[v] += total;
                active_since_settlement += placeable.len();
                if rules.direct_placement() {
                    funds.earmarked -= total;
                }
                let ids = if !rules.direct_placement() {
                    // Placed at the next settlement, netted with everything else.
                    Vec::new()
                } else if rules.reserve_percent == 0 {
                    funds.move_in(v, total);
                    batch_events(
                        &mut events,
                        t,
                        EventKind::Placement,
                        &rules.account,
                        &vault.contract,
                        placeable.iter().flat_map(|&i| profiles[i].notes.clone()),
                    )
                } else {
                    let kept = funds.cut_down(total * (100 - u64::from(rules.reserve_percent)) / 100);
                    funds.move_in(v, kept);
                    funds.emit(&mut events, t, EventKind::Placement, &rules.account, &vault.contract, kept)
                };
                for &i in &placeable {
                    states[i].placed_at = Some(t);
                    states[i].placements = ids.clone();
                }
            }

            let leaving: Vec<usize> = (0..users.len())
                .filter(in_vault)
                .filter(|&i| {
                    let p = &profiles[i];
                    states[i].placed_at.is_some_and(|placed| placed < t)
                        && states[i].withdrawn_at.is_none()
                        && p.exit_at <= t
                        && p.request_at + rules.min_stay_secs <= t
                })
                .collect();
            if withdraw_at[v].is_none() && leaving.len() >= rules.k {
                withdraw_at[v] = Some(t + rng.gen_range(0..rules.window_secs));
            }
            if withdraw_at[v] == Some(t) {
                let total: u64 = leaving.iter().map(|&i| notes_amount(&profiles[i].exit_notes)).sum();
                if rules.direct_exit() && funds.vaults[v] < total {
                    // Noise has lent part of this vault out; wait for it to come back.
                    withdraw_at[v] = Some(t + 1);
                    continue;
                }
                withdraw_at[v] = None;
                owed[v] -= total;
                active_since_settlement += leaving.len();
                let ids = if rules.direct_exit() {
                    funds.move_out(v, total);
                    batch_events(
                        &mut events,
                        t,
                        EventKind::Withdrawal,
                        &vault.contract,
                        &rules.account,
                        leaving.iter().flat_map(|&i| profiles[i].exit_notes.clone()),
                    )
                } else {
                    Vec::new()
                };
                for &i in &leaving {
                    states[i].withdrawn_at = Some(t);
                    states[i].withdrawals = ids.clone();
                    for n in profiles[i].exit_notes.clone() {
                        for _ in 0..n.count {
                            let due = t + rng.gen_range(1..=rules.exit_window_secs);
                            if rules.direct_exit() {
                                funds.liquid -= n.denomination;
                                events.push(Pending {
                                    at: due,
                                    kind: EventKind::ExitPayment,
                                    from: rules.account.clone(),
                                    to: users[i].account(),
                                    denomination: n.denomination,
                                    count: 1,
                                });
                                states[i].payments.push(events.len() - 1);
                            } else {
                                queue.push(QueuedPayment { due, seq, user: i, denomination: n.denomination });
                                seq += 1;
                            }
                        }
                    }
                }
            }
        }

        // Noise: one-note round trips between vaults, unrelated to any request.
        let agent = rules.account.as_str();
        let mut still_out = Vec::new();
        for r in returns.drain(..) {
            if r.due <= t && funds.vaults[r.to] >= r.denomination {
                funds.move_out(r.to, r.denomination);
                funds.move_in(r.from, r.denomination);
                funds.offsets[r.to] -= r.denomination as i64;
                funds.offsets[r.from] += r.denomination as i64;
                funds.emit(&mut events, t, EventKind::Withdrawal, &config.vaults[r.to].contract, agent, r.denomination);
                funds.emit(&mut events, t, EventKind::Placement, agent, &config.vaults[r.from].contract, r.denomination);
            } else {
                still_out.push(r);
            }
        }
        returns = still_out;
        if acting && rules.noise_moves_per_hour > 0 && rng.gen_bool(f64::from(rules.noise_moves_per_hour) / 3600.0) {
            let sources: Vec<usize> = (0..vault_count).filter(|&v| funds.vaults[v] >= funds.smallest).collect();
            if !sources.is_empty() {
                let from = sources[rng.gen_range(0..sources.len())];
                let fitting: Vec<u64> =
                    config.denominations.iter().copied().filter(|&d| d <= funds.vaults[from]).collect();
                let denomination = fitting[rng.gen_range(0..fitting.len())];
                let mut to = rng.gen_range(0..vault_count - 1);
                if to >= from {
                    to += 1;
                }
                funds.move_out(from, denomination);
                funds.move_in(to, denomination);
                funds.offsets[from] -= denomination as i64;
                funds.offsets[to] += denomination as i64;
                funds.emit(&mut events, t, EventKind::Withdrawal, &config.vaults[from].contract, agent, denomination);
                funds.emit(&mut events, t, EventKind::Placement, agent, &config.vaults[to].contract, denomination);
                let due = t + rng.gen_range(1..=rules.window_secs);
                returns.push(NoiseReturn { due, from, to, denomination });
            }
        }

        // Net settlement: each vault is brought to what it owes, less the reserve, plus noise on loan.
        let period = rules.settlement_period_secs;
        let busy_enough = active_since_settlement >= rules.min_active_per_settlement || t > config.run_secs;
        if period > 0 && t > 0 && t % period == 0 && busy_enough {
            active_since_settlement = 0;
            let desired: Vec<u64> = (0..vault_count)
                .map(|v| {
                    let kept = funds.cut_down(owed[v] * (100 - u64::from(rules.reserve_percent)) / 100);
                    (kept as i64 + funds.offsets[v]).max(0) as u64
                })
                .collect();
            for (v, &want) in desired.iter().enumerate() {
                if funds.vaults[v] > want {
                    let moved = funds.cut_down(funds.vaults[v] - want);
                    funds.move_out(v, moved);
                    funds.emit(&mut events, t, EventKind::Withdrawal, &config.vaults[v].contract, agent, moved);
                }
            }
            for (v, &want) in desired.iter().enumerate() {
                if funds.vaults[v] < want {
                    let moved = funds.cut_down((want - funds.vaults[v]).min(funds.liquid));
                    funds.move_in(v, moved);
                    funds.emit(&mut events, t, EventKind::Placement, agent, &config.vaults[v].contract, moved);
                }
            }
        }

        // Exits paid from the reserve, refilled from the fullest vault when it runs short.
        if !rules.direct_exit() {
            queue.sort_by_key(|p| (p.due, p.seq));
            let due_now: u64 = queue.iter().filter(|p| p.due <= t).map(|p| p.denomination).sum();
            if period == 0 && due_now > funds.available() {
                let reserve = (funds.liquid + funds.vaults.iter().sum::<u64>()) * u64::from(rules.reserve_percent) / 100;
                if let Some(v) = (0..vault_count).max_by_key(|&v| (funds.vaults[v], std::cmp::Reverse(v))) {
                    let wanted = due_now - funds.available() + reserve;
                    let moved = funds.cut_down(funds.round_up(wanted).min(funds.vaults[v]));
                    funds.move_out(v, moved);
                    funds.emit(&mut events, t, EventKind::Withdrawal, &config.vaults[v].contract, agent, moved);
                }
            }
            while let Some(p) = queue.first() {
                if p.due > t || funds.available() < p.denomination {
                    break;
                }
                let p = queue.remove(0);
                funds.liquid -= p.denomination;
                events.push(Pending {
                    at: t,
                    kind: EventKind::ExitPayment,
                    from: rules.account.clone(),
                    to: users[p.user].account(),
                    denomination: p.denomination,
                    count: 1,
                });
                states[p.user].payments.push(events.len() - 1);
            }
        }
        t += 1;
    }

    // Public ids follow time; ties keep the order in which events were made.
    let mut order: Vec<usize> = (0..events.len()).collect();
    order.sort_by_key(|&i| events[i].at);
    let mut public_id = vec![0; events.len()];
    for (id, &i) in order.iter().enumerate() {
        public_id[i] = id;
    }
    let timeline = order
        .iter()
        .enumerate()
        .map(|(id, &i)| {
            let e = &events[i];
            PublicEvent {
                id,
                at_secs: e.at,
                kind: e.kind,
                from: e.from.clone(),
                to: e.to.clone(),
                denomination: e.denomination,
                count: e.count,
                amount: e.denomination * u64::from(e.count),
            }
        })
        .collect();
    let remap = |ids: &[usize]| ids.iter().map(|&i| public_id[i]).collect::<Vec<_>>();
    let requests = states
        .iter()
        .zip(profiles)
        .zip(&users)
        .map(|((s, profile), u)| RequestTruth {
            user: u.index,
            account: u.account(),
            vault: config.vaults[profile.vault].contract.clone(),
            placed_at: s.placed_at,
            withdrawn_at: s.withdrawn_at,
            deposit_events: remap(&s.deposits),
            placement_events: remap(&s.placements),
            withdrawal_events: remap(&s.withdrawals),
            payment_events: remap(&s.payments),
            profile,
        })
        .collect();
    Ok(Simulation { users, timeline, truth: Truth { requests } })
}


/// Creates a file only its owner can read. Refuses to replace an existing one.
pub fn create_private(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {} (it must not exist yet)", path.display()))
}

fn account_key_text(key: &SigningKey) -> String {
    let mut bytes = key.to_bytes().to_vec();
    bytes.extend_from_slice(key.verifying_key().as_bytes());
    format!("ed25519:{}", bs58::encode(bytes).into_string())
}

/// Writes every user's key, in the `ed25519:<base58>` form NEAR tools read, to a new file readable
/// by its owner only. Nothing else ever prints them.
pub fn write_keys(path: &Path, users: &[FakeUser]) -> Result<()> {
    let entries: Vec<serde_json::Value> = users
        .iter()
        .map(|u| {
            serde_json::json!({
                "account": u.account(),
                "secret_key": account_key_text(&u.key),
            })
        })
        .collect();
    let mut file = create_private(path)?;
    file.write_all(serde_json::to_string_pretty(&entries)?.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
