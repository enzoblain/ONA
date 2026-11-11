//! How well the vault each user chose stays hidden, measured on the public timeline only.
//!
//! **The figures are an upper bound on privacy.** The elimination below only applies necessary
//! conditions, so it never excludes a user's true vault, but a stronger observer (a full search over
//! every possible assignment, or statistics over many runs) can exclude more. Real privacy is at most
//! what is measured here.

use std::collections::{BTreeMap, BTreeSet};

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
                for (w, wb) in withdrawals.iter().enumerate() {
                    if wb.vault == b.vault
                        && wb.at > b.at
                        && wb.at >= f.first_deposit + rules.min_stay_secs
                        && wb.at < first
                        && last <= wb.at + rules.exit_window_secs
                        && covers(&wb.notes, &f.paid)
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

    let joint = rules.direct_exit() && rules.noise_moves_per_hour == 0;
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

/// How often two simple guesses find a user's vault, scored against the ground truth.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Guesses {
    /// Guess the vault of the first placement at least `min_wait_secs` after the deposit. Share of
    /// placed users guessed right.
    pub first_placement: Option<f64>,
    /// Guess the vault of the last withdrawal before the first exit payment. Share of paid users
    /// guessed right.
    pub last_withdrawal: Option<f64>,
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
    let (mut placed, mut placed_hits, mut paid, mut paid_hits) = (0, 0, 0, 0);
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
        }
    }
    Guesses {
        first_placement: share(placed_hits, placed),
        last_withdrawal: share(paid_hits, paid),
        most_chosen: share(chosen.values().copied().max().unwrap_or(0), placed),
    }
}
