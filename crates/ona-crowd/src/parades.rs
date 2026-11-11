//! Compares countermeasures against the user to vault leak, over several seeds.

use std::collections::BTreeSet;

use anyhow::Result;

use crate::{guesses, privacy, simulate, Config, EventKind, PublicEvent, Sizes};

/// One set of countermeasures. All zero is the agent without any.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: String,
    pub reserve_percent: u8,
    pub settlement_period_secs: u64,
    pub noise_moves_per_hour: u32,
}

/// The agent without countermeasures, each one alone, and their combinations.
pub fn scenarios(reserve_percent: u8, settlement_period_secs: u64, noise_moves_per_hour: u32) -> Vec<Scenario> {
    let s = |name: &str, r: u8, p: u64, n: u32| Scenario {
        name: name.to_string(),
        reserve_percent: r,
        settlement_period_secs: p,
        noise_moves_per_hour: n,
    };
    let (r, p, n) = (reserve_percent, settlement_period_secs, noise_moves_per_hour);
    vec![
        s("none", 0, 0, 0),
        s(&format!("reserve {r}%"), r, 0, 0),
        s(&format!("net settlement every {p} s"), 0, p, 0),
        s(&format!("noise {n}/h"), 0, 0, n),
        s("reserve + settlement", r, p, 0),
        s("reserve + settlement + noise", r, p, n),
    ]
}

/// One line of the comparison, over every seed.
#[derive(Debug, Clone)]
pub struct Row {
    pub name: String,
    /// Share of matched accounts whose vault is certain, all seeds pooled.
    pub exposed_share: f64,
    /// Possible vaults per matched account, all seeds pooled.
    pub vaults: Sizes,
    pub first_placement_guess: Option<f64>,
    pub last_withdrawal_guess: Option<f64>,
    pub most_chosen: Option<f64>,
    /// Agent transactions per run (placements and withdrawals grouped per vault and moment, plus
    /// one per exit payment), on average.
    pub agent_transactions: f64,
    /// Share of users paid out by the end of the run.
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
        let (mut exposed, mut first, mut last, mut most, mut transactions, mut exited) =
            (0, Vec::new(), Vec::new(), Vec::new(), 0, 0);
        let mut joint = true;
        for seed in 1..=seeds {
            let mut config = base.clone();
            config.seed = seed;
            config.agent.reserve_percent = s.reserve_percent;
            config.agent.settlement_period_secs = s.settlement_period_secs;
            config.agent.noise_moves_per_hour = s.noise_moves_per_hour;
            let sim = simulate(&config)?;
            let p = privacy(&sim.timeline, &config);
            exposed += p.exposed;
            sizes.extend(p.vaults.sizes);
            joint &= p.joint;
            let g = guesses(&sim, &config);
            first.push(g.first_placement);
            last.push(g.last_withdrawal);
            most.push(g.most_chosen);
            transactions += agent_transactions(&sim.timeline);
            exited += sim.truth.requests.iter().filter(|r| !r.payment_events.is_empty()).count();
        }
        let matched = sizes.len();
        rows.push(Row {
            name: s.name.clone(),
            exposed_share: if matched == 0 { 0.0 } else { exposed as f64 / matched as f64 },
            vaults: Sizes::new(sizes),
            first_placement_guess: mean(&first),
            last_withdrawal_guess: mean(&last),
            most_chosen: mean(&most),
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
        "| Countermeasure | Vault certain | Possible vaults, median / min | First-placement guess | Last-withdrawal guess | Blind guess | Agent tx per run | Extra tx | Paid out |\n\
         |---|---|---|---|---|---|---|---|---|\n",
    );
    for r in rows {
        let vaults = match (r.vaults.median, r.vaults.minimum) {
            (Some(m), Some(n)) => format!("{m} / {n}"),
            _ => "-".into(),
        };
        out.push_str(&format!(
            "| {} | {:.0} %{} | {} | {} | {} | {} | {:.0} | {:+.0} | {:.0} % |\n",
            r.name,
            r.exposed_share * 100.0,
            if r.joint { "" } else { " *" },
            vaults,
            percent(r.first_placement_guess),
            percent(r.last_withdrawal_guess),
            percent(r.most_chosen),
            r.agent_transactions,
            r.agent_transactions - base,
            r.exited_share * 100.0,
        ));
    }
    out
}
