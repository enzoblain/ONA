//! Compares countermeasures against the user to vault leak, over several seeds.

use std::collections::BTreeSet;

use anyhow::Result;

use crate::{guesses, posterior, privacy, simulate, yield_guess, Config, EventKind, PublicEvent, Sizes, YieldMode};

/// Steps of the sampler per account, for each run.
pub const SAMPLER_STEPS: usize = 200;

/// One variant of the configuration.
pub struct Scenario {
    pub name: String,
    pub apply: Box<dyn Fn(&mut Config)>,
}

fn scenario(name: impl Into<String>, apply: impl Fn(&mut Config) + 'static) -> Scenario {
    Scenario { name: name.into(), apply: Box::new(apply) }
}

/// The agent without countermeasures, each one alone, their combinations, and separate accounting
/// (reserve, net settlement and a minimum of active requests per settlement).
pub fn scenarios(reserve: u8, period: u64, noise: u32) -> Vec<Scenario> {
    let min_active = 10;
    vec![
        scenario("none", |_| {}),
        scenario(format!("reserve {reserve}%"), move |c| c.agent.reserve_percent = reserve),
        scenario(format!("net settlement every {period} s"), move |c| c.agent.settlement_period_secs = period),
        scenario(format!("noise {noise}/h"), move |c| c.agent.noise_moves_per_hour = noise),
        scenario("reserve + settlement + noise", move |c| {
            c.agent.reserve_percent = reserve;
            c.agent.settlement_period_secs = period;
            c.agent.noise_moves_per_hour = noise;
        }),
        scenario(format!("separate accounting (reserve, settlement, at least {min_active} active)"), move |c| {
            separate(c, reserve, period, min_active)
        }),
        scenario("separate accounting + steady withdrawals (10 units per vault every 600 s)", move |c| {
            separate(c, reserve, period, min_active);
            c.agent.steady_withdrawal_period_secs = 600;
            c.agent.steady_withdrawal_units = 10;
        }),
        scenario("separate accounting + 30% switch vault while placed", move |c| {
            separate(c, reserve, period, min_active);
            c.agent.switch_percent = 30;
        }),
    ]
}

fn separate(c: &mut Config, reserve: u8, period: u64, min_active: usize) {
    c.agent.reserve_percent = reserve;
    c.agent.settlement_period_secs = period;
    c.agent.min_active_per_settlement = min_active;
}

/// Yield leak: no yield, pooled yield, then individual yield (the product's choice) with 0, 30 and 60
/// percent of users accepting a suggestion. All with separate accounting, since that is the
/// recommended agent. `base` must give the vault rates.
pub fn yield_scenarios(reserve: u8, period: u64) -> Vec<Scenario> {
    let accounting = move |c: &mut Config| separate(c, reserve, period, 10);
    let mut out = vec![
        scenario("no yield", move |c| {
            accounting(c);
            c.yield_bp_per_hour.clear();
        }),
        scenario("pooled yield", move |c| {
            accounting(c);
            c.yield_mode = YieldMode::Pooled;
        }),
    ];
    for s in [0u8, 30, 60] {
        out.push(scenario(format!("individual yield, {s}% follow suggestions"), move |c| {
            accounting(c);
            c.yield_mode = YieldMode::Individual;
            c.suggestion_percent = s;
        }));
    }
    out
}

/// One line of the comparison, over every seed.
#[derive(Debug, Clone)]
pub struct Row {
    pub name: String,
    /// Share of matched accounts whose vault is certain, all seeds pooled: an upper bound on privacy.
    pub exposed_share: f64,
    pub vaults: Sizes,
    /// Highest chance, over all seeds, of guessing the worst-off user's vault.
    pub worst_max: Option<f64>,
    pub mean_entropy_bits: Option<f64>,
    /// Share of users found by taking the most probable vault.
    pub observer_success: Option<f64>,
    pub blind: Option<f64>,
    pub last_withdrawal_guess: Option<f64>,
    pub nearest_yield_guess: Option<f64>,
    pub yield_guess: Option<f64>,
    /// Share of placed users the sampler can never move (unique amount or timing).
    pub frozen_share: f64,
    /// Sampled states that failed to replay the public timeline. Must be zero.
    pub replay_failures: usize,
    /// Share of the yield users would have earned at the rate of the vault they first wanted, given
    /// up by following a suggestion or, with pooled yield, by sharing the pool's average rate.
    pub yield_lost: Option<f64>,
    pub agent_transactions: f64,
    pub exited_share: f64,
    pub joint: bool,
}

/// Agent transactions in a timeline: one per vault and moment for each kind of move, one per payment.
pub fn agent_transactions(timeline: &[PublicEvent]) -> usize {
    let moves: BTreeSet<(u64, bool, &str)> = timeline
        .iter()
        .filter_map(|e| match e.kind {
            EventKind::Placement => Some((e.at_secs, true, e.to.as_str())),
            EventKind::Withdrawal => Some((e.at_secs, false, e.from.as_str())),
            _ => None,
        })
        .collect();
    moves.len() + timeline.iter().filter(|e| e.kind == EventKind::ExitPayment).count()
}

fn mean(values: &[Option<f64>]) -> Option<f64> {
    let known: Vec<f64> = values.iter().flatten().copied().collect();
    (!known.is_empty()).then(|| known.iter().sum::<f64>() / known.len() as f64)
}

/// Runs every scenario on seeds `1..=seeds`, everything else taken from `base`.
pub fn compare(base: &Config, scenarios: &[Scenario], seeds: u64) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for s in scenarios {
        let mut sizes = Vec::new();
        let (mut exposed, mut transactions, mut exited) = (0, 0, 0);
        let (mut worst, mut entropy, mut success, mut blind, mut last, mut rate, mut credit) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let (mut frozen, mut placed, mut replay_failures) = (0usize, 0usize, 0usize);
        let (mut lost, mut wanted) = (0u64, 0u64);
        let mut joint = true;
        for seed in 1..=seeds {
            let mut config = base.clone();
            config.seed = seed;
            (s.apply)(&mut config);
            let sim = simulate(&config)?;
            let p = privacy(&sim.timeline, &config);
            exposed += p.exposed;
            sizes.extend(p.vaults.sizes);
            joint &= p.joint;
            let post = posterior(&sim, &config, SAMPLER_STEPS);
            worst.push(post.worst_max);
            entropy.push(post.mean_entropy_bits);
            success.push(post.success);
            blind.push(post.blind);
            frozen += post.frozen;
            placed += post.users;
            replay_failures += post.replay_failures;
            let g = guesses(&sim, &config);
            last.push(g.last_withdrawal);
            credit.push(g.nearest_yield);
            rate.push(yield_guess(&sim, &config));
            for r in sim.truth.requests.iter().filter(|r| r.withdrawn_at.is_some()) {
                wanted += r.wanted_gain;
                lost += r.wanted_gain.saturating_sub(r.gain);
            }
            transactions += agent_transactions(&sim.timeline);
            exited += sim.truth.requests.iter().filter(|r| !r.payment_events.is_empty()).count();
        }
        let matched = sizes.len();
        rows.push(Row {
            name: s.name.clone(),
            exposed_share: if matched == 0 { 0.0 } else { exposed as f64 / matched as f64 },
            vaults: Sizes::new(sizes),
            worst_max: worst.iter().flatten().copied().reduce(f64::max),
            mean_entropy_bits: mean(&entropy),
            observer_success: mean(&success),
            blind: mean(&blind),
            last_withdrawal_guess: mean(&last),
            nearest_yield_guess: mean(&credit),
            yield_guess: mean(&rate),
            frozen_share: if placed == 0 { 0.0 } else { frozen as f64 / placed as f64 },
            replay_failures,
            yield_lost: (wanted > 0).then(|| lost as f64 / wanted as f64),
            agent_transactions: transactions as f64 / seeds as f64,
            exited_share: exited as f64 / (seeds as f64 * base.users as f64),
            joint,
        });
    }
    Ok(rows)
}

fn percent(value: Option<f64>) -> String {
    value.map_or("-".into(), |v| format!("{:.0} %", v * 100.0))
}

/// The comparison as a Markdown table. Extra transactions are counted against the first row.
pub fn table(rows: &[Row]) -> String {
    let base = rows.first().map_or(0.0, |r| r.agent_transactions);
    let mut out = String::from(
        "| Countermeasure | Vault certain (bound) | Frozen users | Entropy | Observer finds | Blind | Last-withdrawal guess | Reward-credit guess | Rate guess | Yield given up | Agent tx | Extra tx | Paid out |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for r in rows {
        out.push_str(&format!(
            "| {} | {:.0} %{} | {:.0} % | {} | {} | {} | {} | {} | {} | {} | {:.0} | {:+.0} | {:.0} % |\n",
            r.name,
            r.exposed_share * 100.0,
            if r.joint { "" } else { " *" },
            r.frozen_share * 100.0,
            r.mean_entropy_bits.map_or("-".into(), |b| format!("{b:.2} bit")),
            percent(r.observer_success),
            percent(r.blind),
            percent(r.last_withdrawal_guess),
            percent(r.nearest_yield_guess),
            percent(r.yield_guess),
            percent(r.yield_lost),
            r.agent_transactions,
            r.agent_transactions - base,
            r.exited_share * 100.0,
        ));
    }
    out
}
