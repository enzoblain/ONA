//! How well the vault each user chose stays hidden, measured on the public timeline only.
//!
//! **The figures are an upper bound on privacy.** The elimination below only applies necessary
//! conditions, so it never excludes a user's true vault, but a stronger observer (a full search over
//! every possible assignment, or statistics over many runs) can exclude more. Real privacy is at most
//! what is measured here.

use std::collections::{BTreeMap, BTreeSet};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;

use crate::{Config, EventKind, PublicEvent, Simulation};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Privacy {
    /// For each matched account: the vaults it could have chosen.
    pub vaults: Sizes,
    /// For each matched account: the placement batches that could have carried its notes, which
    /// says when the agent may have placed for it.
    pub batches: Sizes,
    /// Matched accounts whose vault is certain: exactly one candidate.
    pub exposed: usize,
    /// Accounts with no possible placement at all, so never placed. Left out of the figures above.
    pub unmatched: usize,
    /// Whether batches were assigned jointly (each batch holds exactly its members' notes). Only
    /// possible when placements and exits follow requests one to one and there is no noise.
    pub joint: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Sizes {
    /// One number per matched account, in the order of their first deposit.
    pub sizes: Vec<usize>,
    pub median: Option<f64>,
    pub minimum: Option<usize>,
}

impl Sizes {
    pub(crate) fn new(sizes: Vec<usize>) -> Self {
        let mut sorted = sizes.clone();
        sorted.sort_unstable();
        let median = match sorted.len() {
            0 => None,
            n if n % 2 == 1 => Some(sorted[n / 2] as f64),
            n => Some((sorted[n / 2 - 1] + sorted[n / 2]) as f64 / 2.0),
        };
        Self { minimum: sorted.first().copied(), sizes, median }
    }
}

/// Notes per denomination.
type Holdings = BTreeMap<u64, u64>;

fn amount(notes: &Holdings) -> u64 {
    notes.iter().map(|(d, n)| d * n).sum()
}

fn covers(batch: &Holdings, needed: &Holdings) -> bool {
    needed.iter().all(|(d, n)| batch.get(d).copied().unwrap_or(0) >= *n)
}

struct Batch {
    vault: usize,
    at: u64,
    notes: Holdings,
}

/// The agent's batches of one kind, grouped by vault and time.
fn batches(timeline: &[PublicEvent], kind: EventKind, vaults: &[String]) -> Vec<Batch> {
    let mut grouped: BTreeMap<(usize, u64), Holdings> = BTreeMap::new();
    for e in timeline.iter().filter(|e| e.kind == kind) {
        let contract = if kind == EventKind::Placement { &e.to } else { &e.from };
        if let Some(vault) = vaults.iter().position(|v| v == contract) {
            *grouped.entry((vault, e.at_secs)).or_default().entry(e.denomination).or_default() += u64::from(e.count);
        }
    }
    grouped.into_iter().map(|((vault, at), notes)| Batch { vault, at, notes }).collect()
}

/// What the public timeline shows about one account.
#[derive(Default)]
struct Footprint {
    first_deposit: u64,
    deposited: Holdings,
    paid: Holdings,
    first_payment: Option<u64>,
    last_payment: Option<u64>,
}

fn footprints(timeline: &[PublicEvent]) -> Vec<(String, Footprint)> {
    let mut accounts: BTreeMap<&str, Footprint> = BTreeMap::new();
    for e in timeline {
        match e.kind {
            EventKind::Deposit => {
                let f = accounts
                    .entry(e.from.as_str())
                    .or_insert_with(|| Footprint { first_deposit: e.at_secs, ..Default::default() });
                f.first_deposit = f.first_deposit.min(e.at_secs);
                *f.deposited.entry(e.denomination).or_default() += u64::from(e.count);
            }
            EventKind::ExitPayment => {
                if let Some(f) = accounts.get_mut(e.to.as_str()) {
                    *f.paid.entry(e.denomination).or_default() += u64::from(e.count);
                    f.first_payment = Some(f.first_payment.map_or(e.at_secs, |t| t.min(e.at_secs)));
                    f.last_payment = Some(f.last_payment.map_or(e.at_secs, |t| t.max(e.at_secs)));
                }
            }
            _ => {}
        }
    }
    let mut out: Vec<(String, Footprint)> = accounts.into_iter().map(|(a, f)| (a.to_string(), f)).collect();
    out.sort_by_key(|(_, f)| f.first_deposit);
    out
}

/// One way an account's funds may have gone: a vault, the placement batch, the withdrawal batch.
/// `vault: None` means never placed, which is possible only for an account never paid.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Route {
    vault: Option<usize>,
    placement: Option<usize>,
    withdrawal: Option<usize>,
}

/// Every route compatible with what the timeline shows of one account, under the public rules.
fn routes(f: &Footprint, placements: &[Batch], withdrawals: &[Batch], vault_count: usize, config: &Config) -> Vec<Route> {
    let rules = &config.agent;
    let paid = f.first_payment.is_some();
    let mut out = Vec::new();
    if !paid {
        out.push(Route { vault: None, placement: None, withdrawal: None });
    }
    if !rules.direct_placement() {
        // Net settlement: what a vault receives no longer says whose notes it carries.
        out.extend((0..vault_count).map(|v| Route { vault: Some(v), placement: None, withdrawal: None }));
        return out;
    }
    let smallest = config.denominations.iter().copied().min().unwrap_or(1);
    let kept = |total: u64| total * (100 - u64::from(rules.reserve_percent)) / 100 / smallest * smallest;
    for (p, b) in placements.iter().enumerate() {
        let carries = if rules.reserve_percent == 0 {
            covers(&b.notes, &f.deposited)
        } else {
            // With a reserve the batch is re-cut into notes: only its amount says anything.
            amount(&b.notes) >= kept(amount(&f.deposited))
        };
        if b.at < f.first_deposit + rules.min_wait_secs || !carries {
            continue;
        }
        match (paid, rules.direct_exit()) {
            (true, true) => {
                let (first, last) = (f.first_payment.unwrap_or(0), f.last_payment.unwrap_or(0));
                // Gains are paid later and mixed with the exit, so with yield only timing counts.
                let yield_on = config.has_yield();
                for (w, wb) in withdrawals.iter().enumerate() {
                    if wb.vault == b.vault
                        && wb.at > b.at
                        && wb.at >= f.first_deposit + rules.min_stay_secs
                        && wb.at < first
                        && (yield_on || (last <= wb.at + rules.exit_window_secs && covers(&wb.notes, &f.paid)))
                    {
                        out.push(Route { vault: Some(b.vault), placement: Some(p), withdrawal: Some(w) });
                    }
                }
            }
            // Exits come from the reserve: no withdrawal belongs to a precise exit.
            _ => out.push(Route { vault: Some(b.vault), placement: Some(p), withdrawal: None }),
        }
    }
    out
}

/// One pass of joint elimination over the batches of one kind. A batch holds exactly the notes of
/// its members, so for each denomination:
/// - if the accounts that can be in it hold exactly its count, each of them with such notes is in it;
/// - an account cannot join if the accounts certainly in it already fill that count.
///
/// Both are necessary conditions, so the true route is never removed. Returns whether anything changed.
fn eliminate(
    candidates: &mut [Vec<Route>],
    notes: &[&Holdings],
    batches: &[Batch],
    batch_of: fn(&Route) -> Option<usize>,
) -> bool {
    let mut changed = false;
    for (b, batch) in batches.iter().enumerate() {
        let denominations: BTreeSet<u64> =
            batch.notes.keys().copied().chain(notes.iter().flat_map(|n| n.keys().copied())).collect();
        for d in denominations {
            let count = batch.notes.get(&d).copied().unwrap_or(0);
            let held = |u: usize| notes[u].get(&d).copied().unwrap_or(0);
            let can: Vec<usize> =
                (0..candidates.len()).filter(|&u| candidates[u].iter().any(|r| batch_of(r) == Some(b))).collect();
            let must: Vec<usize> = can
                .iter()
                .copied()
                .filter(|&u| candidates[u].iter().all(|r| batch_of(r) == Some(b)))
                .collect();
            let can_sum: u64 = can.iter().map(|&u| held(u)).sum();
            let must_sum: u64 = must.iter().map(|&u| held(u)).sum();
            for &u in &can {
                let before = candidates[u].len();
                if count > 0 && can_sum == count && held(u) > 0 {
                    candidates[u].retain(|r| batch_of(r) == Some(b));
                } else if !must.contains(&u) && must_sum + held(u) > count {
                    candidates[u].retain(|r| batch_of(r) != Some(b));
                }
                changed |= candidates[u].len() != before;
            }
        }
    }
    changed
}

/// Measures, for each depositor account, which vaults and placement batches remain possible given
/// only the public timeline and the pool's public rules (which an observer knows).
///
/// Without countermeasures, a placement batch is a candidate when it came at least `min_wait_secs`
/// after the account's deposit and carried at least its notes in every denomination (a request
/// places all its notes in one batch). An account that was paid also needs, in the same vault, a later
/// withdrawal made at least `min_stay_secs` after the deposit, before the first payment, no more than
/// `exit_window_secs` before the last one, carrying at least the notes paid back. Then batches are
/// assigned jointly (see [`eliminate`]) until nothing changes. With a reserve, only amounts and
/// placement times count; with net settlement, nothing ties an account to a vault.
///
/// Deposit time is a lower bound of request time, so the true vault always stays a candidate for an
/// account that was placed.
pub fn privacy(timeline: &[PublicEvent], config: &Config) -> Privacy {
    let (accounts, joint) = candidates(timeline, config);
    let mut vault_sizes = Vec::new();
    let mut batch_sizes = Vec::new();
    let mut unmatched = 0;
    for a in &accounts {
        if a.vaults.is_empty() {
            unmatched += 1;
            continue;
        }
        vault_sizes.push(a.vaults.len());
        batch_sizes.push(a.batches);
    }
    Privacy {
        exposed: vault_sizes.iter().filter(|&&n| n == 1).count(),
        vaults: Sizes::new(vault_sizes),
        batches: Sizes::new(batch_sizes),
        unmatched,
        joint,
    }
}

/// What remains possible for one depositor account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidates {
    pub account: String,
    /// Contracts of the vaults it may have chosen. Empty: it was never placed.
    pub vaults: BTreeSet<String>,
    /// Placement batches that may have carried its notes.
    pub batches: usize,
}

/// The candidates of every depositor account, in the order of their first deposit, and whether the
/// joint assignment was applied. See [`privacy`].
pub fn candidates(timeline: &[PublicEvent], config: &Config) -> (Vec<Candidates>, bool) {
    let rules = &config.agent;
    let vaults: Vec<String> = config.vaults.iter().map(|v| v.contract.clone()).collect();
    let placements = batches(timeline, EventKind::Placement, &vaults);
    let withdrawals = batches(timeline, EventKind::Withdrawal, &vaults);
    let accounts = footprints(timeline);
    let mut routes: Vec<Vec<Route>> =
        accounts.iter().map(|(_, f)| routes(f, &placements, &withdrawals, vaults.len(), config)).collect();

    let joint = rules.direct_exit() && rules.noise_moves_per_hour == 0 && !config.has_yield();
    if joint {
        let deposited: Vec<&Holdings> = accounts.iter().map(|(_, f)| &f.deposited).collect();
        let paid: Vec<&Holdings> = accounts.iter().map(|(_, f)| &f.paid).collect();
        loop {
            let a = eliminate(&mut routes, &deposited, &placements, |r| r.placement);
            let b = eliminate(&mut routes, &paid, &withdrawals, |r| r.withdrawal);
            if !a && !b {
                break;
            }
        }
    }

    let out = routes
        .iter()
        .zip(&accounts)
        .map(|(routes, (account, f))| {
            let possible: BTreeSet<String> = routes.iter().filter_map(|r| r.vault).map(|v| vaults[v].clone()).collect();
            let batches = if possible.is_empty() {
                0
            } else if rules.direct_placement() {
                routes.iter().filter_map(|r| r.placement).collect::<BTreeSet<_>>().len()
            } else {
                placements.iter().filter(|b| b.at >= f.first_deposit + rules.min_wait_secs).count()
            };
            Candidates { account: account.clone(), vaults: possible, batches }
        })
        .collect();
    (out, joint)
}

/// What an observer believes about each placed user's vault, from assignments consistent with the
/// public timeline.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Posterior {
    /// Placed users measured.
    pub users: usize,
    /// Placed users the sampler can never move: no other account shares their deposits, payments
    /// and timing. Their vault always comes out certain, which is an artefact of the sampler.
    pub frozen: usize,
    /// Over all users, the highest probability the observer gives to any one vault. Reaches 100 %
    /// as soon as one user is frozen.
    pub worst_max: Option<f64>,
    /// Average uncertainty about a user's vault, in bits (1 bit = an even choice between two vaults).
    pub mean_entropy_bits: Option<f64>,
    /// Share of users whose vault an observer finds by taking the most probable one (ties split).
    pub success: Option<f64>,
    /// Share of the most chosen vault: what blind guessing achieves.
    pub blind: Option<f64>,
    /// Sampled states replayed against the public quantities they must reproduce.
    pub replayed: usize,
    /// Sampled states that did not reproduce them. Must be zero.
    pub replay_failures: usize,
}

/// Where one account's funds really went: the starting point of the sampling and what each sampled
/// state is replayed against.
#[derive(Debug, Clone)]
pub struct TrueRoute {
    pub account: String,
    /// The vault it ends in, `None` if never placed.
    pub vault: Option<String>,
    /// The vault it was first placed in.
    pub first_vault: Option<String>,
    pub placed_at: Option<u64>,
    pub withdrawn_at: Option<u64>,
    pub switched_at: Option<u64>,
    /// Amount placed (the whole deposit).
    pub placed: u64,
    /// Amount taken out of the pool, gains excluded.
    pub principal_out: u64,
}

/// Number of independent chains, each started from the truth with its own seed.
pub const CHAINS: u64 = 4;

/// [`posterior_from`] with the simulation's ground truth as the starting point.
pub fn posterior(sim: &Simulation, config: &Config, steps_per_account: usize) -> Posterior {
    let amount = |notes: &[crate::Notes]| notes.iter().map(|n| n.denomination * u64::from(n.count)).sum::<u64>();
    let truth: Vec<TrueRoute> = sim
        .truth
        .requests
        .iter()
        .map(|r| TrueRoute {
            account: r.account.clone(),
            vault: r.placed_at.map(|_| r.vault.clone()),
            first_vault: r.placed_at.map(|_| r.first_vault.clone()),
            placed_at: r.placed_at,
            withdrawn_at: r.withdrawn_at,
            switched_at: r.switched_at,
            placed: amount(&r.profile.notes),
            principal_out: if r.withdrawn_at.is_some() { amount(&r.profile.exit_notes) } else { 0 },
        })
        .collect();
    posterior_from(&sim.timeline, config, &truth, &sim.truth.settlements, steps_per_account)
}

/// The quantities of the public timeline that depend on which vault each account is in. Two
/// assignments with the same replay produce the same public timeline.
///
/// - Placement batches: the notes (or, with a reserve, the amount) of their members.
/// - Withdrawal batches: the amount their members take out.
/// - With net settlement: what each vault owes its requests at each settlement that ran, which fixes
///   every settlement move.
/// - With yield: the rewards each vault credits, at the moment they are public.
#[allow(clippy::too_many_arguments)]
fn replay(
    state: &[Option<Route>],
    truth: &[Option<&TrueRoute>],
    accounts: &[(String, Footprint)],
    placements: &[Batch],
    withdrawals: &[Batch],
    vaults: &[String],
    settlements: &[u64],
    config: &Config,
) -> BTreeMap<(u8, u64, u64, u64), u128> {
    let rules = &config.agent;
    let mut out: BTreeMap<(u8, u64, u64, u64), u128> = BTreeMap::new();
    let vault_index = |name: &Option<String>| name.as_ref().and_then(|v| vaults.iter().position(|c| c == v));
    for (i, route) in state.iter().enumerate() {
        let (Some(route), Some(t)) = (route, truth[i]) else { continue };
        let Some(vault) = route.vault else { continue };
        let f = &accounts[i].1;
        if let Some(p) = route.placement {
            if rules.reserve_percent == 0 {
                for (d, n) in &f.deposited {
                    *out.entry((0, p as u64, *d, 0)).or_default() += u128::from(*n);
                }
            } else {
                *out.entry((0, p as u64, 0, 0)).or_default() += u128::from(t.placed);
            }
        }
        if let Some(w) = route.withdrawal {
            *out.entry((1, w as u64, 0, 0)).or_default() += u128::from(t.principal_out);
        }
        // Times travel with the route when it names batches, otherwise they belong to the account.
        let placed_at = route.placement.map(|p| placements[p].at).or(t.placed_at);
        let withdrawn_at = route.withdrawal.map(|w| withdrawals[w].at).or(t.withdrawn_at);
        // A switched account is frozen: its vault before the switch is its true first vault.
        let vault_at = |s: u64| match (t.switched_at, vault_index(&t.first_vault)) {
            (Some(at), Some(first)) if s < at => first,
            _ => vault,
        };
        for &s in settlements {
            let mut owed: i128 = 0;
            if placed_at.is_some_and(|p| p <= s) {
                owed += i128::from(t.placed);
            }
            if withdrawn_at.is_some_and(|w| w <= s) {
                owed -= i128::from(t.principal_out);
            }
            *out.entry((2, s, vault_at(s) as u64, 0)).or_default() += owed as u128;
        }
        if config.has_yield() {
            if let (Some(p), Some(w)) = (placed_at, withdrawn_at) {
                let earned = u128::from(t.principal_out)
                    * u128::from(config.yield_of(vault_at(w)))
                    * u128::from(w - p)
                    / 36_000_000;
                // Credited at the exit, or with the first settlement that ran after it.
                let at = if rules.direct_placement() {
                    w
                } else {
                    settlements.iter().copied().find(|&s| s >= w).unwrap_or(u64::MAX)
                };
                *out.entry((3, at, vault_at(w) as u64, 0)).or_default() += earned;
            }
        }
    }
    out
}

/// Samples assignments of accounts to routes (vault, placement batch, withdrawal batch) by Markov
/// chain Monte Carlo, after Troncoso and Danezis (CCS 2009), and reports what an observer would
/// believe.
///
/// Each chain starts from the true assignment, which explains the timeline, runs half its steps
/// before recording, then records. Each step picks two accounts in the same class and swaps their
/// routes if each route is possible for the other. A class holds accounts with the same deposits and
/// payments; with net settlement, also the same settlements absorbing their placement and their exit
/// (the first settlement that ran at or after each); with yield, outside direct exits, also the same
/// placement and exit moments and amount taken out. Accounts that switched vault are frozen. Every
/// recorded state is replayed (see [`replay`]) and must give the same public quantities as the truth.
/// The proposal is symmetric, so the samples are uniform over the assignments reachable this way.
///
/// **Limits.** Only swaps between identical accounts are tried: an account with a unique amount or
/// timing never moves, and assignments no chain of swaps reaches are never sampled. The observer then
/// looks more certain than a perfect one, so these figures err on the side of less privacy. The
/// chains start from the truth; starting elsewhere would need a consistent assignment, which this
/// does not search for. With pooled yield and net settlement, gains depend on what each vault holds
/// between settlements, which the replay does not cover.
pub fn posterior_from(
    timeline: &[PublicEvent],
    config: &Config,
    truth: &[TrueRoute],
    settlements: &[u64],
    steps_per_account: usize,
) -> Posterior {
    let rules = &config.agent;
    let vaults: Vec<String> = config.vaults.iter().map(|v| v.contract.clone()).collect();
    let placements = batches(timeline, EventKind::Placement, &vaults);
    let withdrawals = batches(timeline, EventKind::Withdrawal, &vaults);
    let accounts = footprints(timeline);
    let possible: Vec<Vec<Route>> =
        accounts.iter().map(|(_, f)| routes(f, &placements, &withdrawals, vaults.len(), config)).collect();
    let truth_by_account: BTreeMap<&str, &TrueRoute> = truth.iter().map(|t| (t.account.as_str(), t)).collect();
    let truth_of: Vec<Option<&TrueRoute>> =
        accounts.iter().map(|(a, _)| truth_by_account.get(a.as_str()).copied()).collect();

    // Starting route of each account: its true one, among those the timeline allows.
    let start: Vec<Option<Route>> = truth_of
        .iter()
        .zip(&possible)
        .map(|(t, routes)| {
            let t = (*t)?;
            let vault = t.vault.as_ref().and_then(|v| vaults.iter().position(|c| c == v));
            let exact = routes.iter().find(|r| {
                r.vault == vault
                    && r.placement.is_none_or(|p| Some(placements[p].at) == t.placed_at)
                    && r.withdrawal.is_none_or(|w| Some(withdrawals[w].at) == t.withdrawn_at)
            });
            exact.or_else(|| routes.iter().find(|r| r.vault == vault)).copied()
        })
        .collect();

    // Accounts whose routes can be swapped without changing anything public.
    let absorbed = |t: Option<u64>| t.map_or(u64::MAX, |t| settlements.iter().copied().find(|&s| s >= t).unwrap_or(u64::MAX));
    type ClassKey = (Vec<(u64, u64)>, Vec<(u64, u64)>, [u64; 5]);
    let mut classes: BTreeMap<ClassKey, Vec<usize>> = BTreeMap::new();
    for (i, (_, f)) in accounts.iter().enumerate() {
        let (Some(_), Some(t)) = (start[i], truth_of[i]) else { continue };
        if t.switched_at.is_some() {
            continue;
        }
        let mut timing = [0u64; 5];
        if !rules.direct_placement() {
            timing[0] = absorbed(t.placed_at);
            timing[1] = absorbed(t.withdrawn_at);
        }
        if config.has_yield() && !rules.direct_exit() {
            timing[2] = t.placed_at.unwrap_or(u64::MAX);
            timing[3] = t.withdrawn_at.unwrap_or(u64::MAX);
            timing[4] = t.principal_out;
        }
        let key = (f.deposited.clone().into_iter().collect(), f.paid.clone().into_iter().collect(), timing);
        classes.entry(key).or_default().push(i);
    }
    let classes: Vec<Vec<usize>> = classes.into_values().filter(|c| c.len() > 1).collect();
    let movable: BTreeSet<usize> = classes.iter().flatten().copied().collect();
    let pairs: Vec<u64> = classes.iter().map(|c| (c.len() * (c.len() - 1) / 2) as u64).collect();
    let total_pairs: u64 = pairs.iter().sum();

    let reference = replay(&start, &truth_of, &accounts, &placements, &withdrawals, &vaults, settlements, config);
    let mut counts: Vec<BTreeMap<usize, u64>> = vec![BTreeMap::new(); accounts.len()];
    let (mut replayed, mut replay_failures) = (0usize, 0usize);
    let steps = (steps_per_account.max(1) * accounts.len().max(1)).div_ceil(CHAINS as usize);
    let burn_in = steps / 2;
    let thin = accounts.len().max(1);
    for chain in 0..CHAINS {
        let mut state = start.clone();
        let mut rng = ChaCha20Rng::seed_from_u64(config.seed ^ 0x05EE_D0FB_A7E5 ^ (chain << 40));
        for step in 0..steps {
            if total_pairs > 0 {
                let mut pick = rng.gen_range(0..total_pairs);
                let c = pairs.iter().position(|&n| {
                    if pick < n {
                        true
                    } else {
                        pick -= n;
                        false
                    }
                });
                let class = &classes[c.unwrap_or(0)];
                let ia = rng.gen_range(0..class.len());
                let mut ib = rng.gen_range(0..class.len() - 1);
                if ib >= ia {
                    ib += 1;
                }
                let (a, b) = (class[ia], class[ib]);
                if let (Some(ra), Some(rb)) = (state[a], state[b]) {
                    if possible[a].contains(&rb) && possible[b].contains(&ra) {
                        state[a] = Some(rb);
                        state[b] = Some(ra);
                    }
                }
            }
            let last = step + 1 == steps;
            if (step >= burn_in && (step - burn_in).is_multiple_of(thin)) || (last && steps <= burn_in) {
                for (i, r) in state.iter().enumerate() {
                    if let Some(v) = r.and_then(|r| r.vault) {
                        *counts[i].entry(v).or_default() += 1;
                    }
                }
                replayed += 1;
                if replay(&state, &truth_of, &accounts, &placements, &withdrawals, &vaults, settlements, config) != reference {
                    replay_failures += 1;
                }
            }
        }
    }

    // Scored on accounts that really were placed.
    let (mut users, mut frozen, mut worst, mut entropy, mut success) = (0usize, 0usize, 0f64, 0f64, 0f64);
    let mut chosen: BTreeMap<usize, usize> = BTreeMap::new();
    for i in 0..accounts.len() {
        let Some(t) = truth_of[i] else { continue };
        let Some(true_vault) = t.vault.as_ref().and_then(|v| vaults.iter().position(|c| c == v)) else { continue };
        users += 1;
        frozen += usize::from(!movable.contains(&i));
        *chosen.entry(true_vault).or_default() += 1;
        let total: u64 = counts[i].values().sum();
        let probabilities: Vec<(usize, f64)> = if total == 0 {
            (0..vaults.len()).map(|v| (v, 1.0 / vaults.len() as f64)).collect()
        } else {
            counts[i].iter().map(|(&v, &n)| (v, n as f64 / total as f64)).collect()
        };
        let best = probabilities.iter().map(|(_, p)| *p).fold(0.0, f64::max);
        worst = worst.max(best);
        entropy -= probabilities.iter().filter(|(_, p)| *p > 0.0).map(|(_, p)| p * p.log2()).sum::<f64>();
        let top: Vec<usize> = probabilities.iter().filter(|(_, p)| (*p - best).abs() < 1e-12).map(|(v, _)| *v).collect();
        if top.contains(&true_vault) {
            success += 1.0 / top.len() as f64;
        }
    }
    let n = users as f64;
    Posterior {
        users,
        frozen,
        worst_max: (users > 0).then_some(worst),
        mean_entropy_bits: (users > 0).then(|| entropy / n),
        success: (users > 0).then(|| success / n),
        blind: (users > 0).then(|| chosen.values().copied().max().unwrap_or(0) as f64 / n),
        replayed,
        replay_failures,
    }
}

/// Share of placed and paid users whose vault an observer finds from their rate alone: the gain
/// (everything paid back minus everything deposited) over the deposit and the time between deposit
/// and first payment, less the delays the public rules impose, matched to the nearest vault rate. `None` without yield. Meaningful only with
/// full exits, since a partial exit hides how much of the deposit came back.
pub fn yield_guess(sim: &Simulation, config: &Config) -> Option<f64> {
    if !config.has_yield() {
        return None;
    }
    let (mut tried, mut hits) = (0usize, 0usize);
    for r in sim.truth.requests.iter().filter(|r| r.placed_at.is_some() && !r.payment_events.is_empty()) {
        let deposited: u64 = r.deposit_events.iter().map(|&i| sim.timeline[i].amount).sum();
        let paid: u64 = r.payment_events.iter().map(|&i| sim.timeline[i].amount).sum();
        let first_payment = r.payment_events.iter().map(|&i| sim.timeline[i].at_secs).min().unwrap_or(0);
        // The rules are public: take off the wait before placing and half of each random window.
        let offset = config.agent.min_wait_secs + config.agent.window_secs / 2 + config.agent.exit_window_secs / 2;
        let duration = first_payment.saturating_sub(r.profile.deposit_at).saturating_sub(offset).max(1);
        let rate = (paid as f64 - deposited as f64) * 36_000_000.0 / (deposited as f64 * duration as f64);
        let guess = (0..config.vaults.len())
            .min_by(|&a, &b| {
                let da = (rate - config.yield_of(a) as f64).abs();
                let db = (rate - config.yield_of(b) as f64).abs();
                da.total_cmp(&db).then(a.cmp(&b))
            })
            .unwrap_or(0);
        tried += 1;
        hits += usize::from(config.vaults[guess].contract == r.vault);
    }
    share(hits, tried)
}

/// How often simple guesses find a user's vault, scored against the ground truth.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Guesses {
    /// Guess the vault of the first placement at least `min_wait_secs` after the deposit. Share of
    /// placed users guessed right.
    pub first_placement: Option<f64>,
    /// Guess the vault of the last withdrawal before the first exit payment. Share of paid users
    /// guessed right.
    pub last_withdrawal: Option<f64>,
    /// Guess the vault whose reward credit (public `Yield` event) is closest in time to the first exit
    /// payment. Share of paid users guessed right; `None` without yield.
    pub nearest_yield: Option<f64>,
    /// Always guessing the most chosen vault: what blind guessing achieves.
    pub most_chosen: Option<f64>,
}

fn share(hits: usize, total: usize) -> Option<f64> {
    (total > 0).then(|| hits as f64 / total as f64)
}

/// Runs two timing guesses that need no assignment at all. A countermeasure that helps should bring
/// both close to `most_chosen`.
pub fn guesses(sim: &Simulation, config: &Config) -> Guesses {
    let rules = &config.agent;
    let vault_of = |e: &PublicEvent| if e.kind == EventKind::Placement { e.to.clone() } else { e.from.clone() };
    let (mut placed, mut placed_hits, mut paid, mut paid_hits, mut yield_hits) = (0, 0, 0, 0, 0);
    let credits: Vec<&PublicEvent> = sim.timeline.iter().filter(|e| e.kind == EventKind::Yield).collect();
    let mut chosen: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &sim.truth.requests {
        if r.placed_at.is_none() {
            continue;
        }
        placed += 1;
        *chosen.entry(r.vault.as_str()).or_default() += 1;
        let from = r.profile.deposit_at + rules.min_wait_secs;
        if let Some(e) = sim.timeline.iter().find(|e| e.kind == EventKind::Placement && e.at_secs >= from) {
            placed_hits += usize::from(vault_of(e) == r.vault);
        }
        let first_payment = r.payment_events.iter().map(|&i| sim.timeline[i].at_secs).min();
        if let Some(first) = first_payment {
            paid += 1;
            let last = sim.timeline.iter().rev().find(|e| e.kind == EventKind::Withdrawal && e.at_secs < first);
            if let Some(e) = last {
                paid_hits += usize::from(vault_of(e) == r.vault);
            }
            if let Some(e) = credits.iter().min_by_key(|e| e.at_secs.abs_diff(first)) {
                yield_hits += usize::from(e.from == r.vault);
            }
        }
    }
    Guesses {
        first_placement: share(placed_hits, placed),
        last_withdrawal: share(paid_hits, paid),
        nearest_yield: if credits.is_empty() { None } else { share(yield_hits, paid) },
        most_chosen: share(chosen.values().copied().max().unwrap_or(0), placed),
    }
}
