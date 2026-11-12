//! When the agent moves the vaults' money. A pure function of the chain's figures, the parameters and what the agent
//! remembers, so it can be tested without a chain. It follows the countermeasures the crowd simulator measured
//! (`crates/ona-crowd/PARADES.md`), all off unless configured:
//!
//! - **reserve**: part of each vault's assets stays liquid, so leaves are paid without waiting for an unstake;
//! - **net settlement**: placing and unstaking happen only at multiples of the settlement period, the net difference
//!   per vault, and only once at least `min_active` entries or leaves happened since the last one;
//! - **steady withdrawals**: a fixed amount is unstaked from every vault at the start of each period of a fixed grid
//!   (multiples of the period), whatever the requests. The period must be a multiple of 3 days, since the contract
//!   allows the agent one `unstake` of its own per vault every 3 days. A withdrawal runs only within `STEADY_SLACK_NS`
//!   of its grid line: if the agent was down, or a settlement's unstake came less than 3 days before, that line is
//!   skipped rather than run late, so the timing never follows the users.
//!
//! What queued leaves will need (`demand`) is added to each vault's reserve, so the funds are liquid when the batch
//! runs.
//!
//! It respects the contract's rules: no placement while an announcement is pending, in a frozen or open vault, or
//! above the hourly cap; at most one `unstake` of the agent's own per vault every `UNSTAKE_INTERVAL_NS`; unstaked
//! funds are withdrawn only after `unbond_wait_ns` (how long a staking pool holds them is not verified); a vault busy
//! with another operation is left alone. Vaults holding shares or placed funds are synced before their reading is an
//! hour old, which also keeps the agent active so the escape does not open.

use serde_json::{json, Value};

use crate::chain::{ConfigInfo, VaultInfo};

/// `ona-pool` `UNSTAKE_INTERVAL_NS`.
pub const UNSTAKE_INTERVAL_NS: u64 = 3 * 24 * 3_600_000_000_000;
/// A steady withdrawal runs this close after its grid line, or not at all.
pub const STEADY_SLACK_NS: u64 = 3_600_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Percent of each vault's assets kept liquid, 0 to 100.
    pub reserve_percent: u8,
    /// 0: settle whenever there is something to move.
    pub settlement_period_ns: u64,
    /// Entries and leaves needed since the last settlement before the next one runs.
    pub min_active: u64,
    /// 0: no steady withdrawals.
    pub steady_period_ns: u64,
    pub steady_amount: u128,
    /// How long unstaked funds wait before `withdraw`.
    pub unbond_wait_ns: u64,
    /// A vault is synced once its reading is this old.
    pub sync_every_ns: u64,
    /// Smaller moves are not worth a transaction.
    pub min_move: u128,
}

/// The defaults follow the simulator's "separate accounting" (reserve 20 %, settlement every 30 minutes, at least 10
/// entries or leaves per settlement); steady withdrawals stay off unless an amount is set.
impl Default for Params {
    fn default() -> Self {
        Self {
            reserve_percent: 20,
            settlement_period_ns: 30 * 60_000_000_000,
            min_active: 10,
            steady_period_ns: 0,
            steady_amount: 0,
            unbond_wait_ns: 4 * 24 * 3_600_000_000_000,
            sync_every_ns: 45 * 60_000_000_000,
            min_move: 1_000_000_000_000_000_000_000_000,
        }
    }
}

impl Params {
    /// Refuses settings the contract would turn into something else.
    pub fn check(&self) -> Result<(), String> {
        if self.reserve_percent > 100 {
            return Err("the reserve is above 100 %".into());
        }
        if self.steady_period_ns != 0 && self.steady_period_ns % UNSTAKE_INTERVAL_NS != 0 {
            return Err("the steady withdrawal period must be a multiple of 3 days (259200 seconds)".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Sync(u32),
    Place(u32, u128),
    Unstake(u32, u128),
    Withdraw(u32, u128),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultMemory {
    pub last_unstake: u64,
    /// Unstaked and not withdrawn yet, as far as the agent knows.
    pub unstaked: u128,
    pub unstaked_at: u64,
    pub last_steady: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Memory {
    /// The settlement period index of the last settlement.
    pub last_slot: u64,
    /// Entries and leaves since the last settlement.
    pub activity: u64,
    pub vaults: Vec<VaultMemory>,
    /// The last processing window whose batch was sent (`service::QueueParams`).
    pub last_window: Option<u64>,
}

fn num(v: &Value) -> u128 {
    v.as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
}

impl Memory {
    pub fn to_json(&self) -> Value {
        json!({
            "last_slot": self.last_slot, "activity": self.activity, "last_window": self.last_window,
            "vaults": self.vaults.iter().map(|v| json!({
                "last_unstake": v.last_unstake, "unstaked": v.unstaked.to_string(),
                "unstaked_at": v.unstaked_at, "last_steady": v.last_steady,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(v: &Value) -> Self {
        Self {
            last_slot: v["last_slot"].as_u64().unwrap_or(0),
            activity: v["activity"].as_u64().unwrap_or(0),
            last_window: v["last_window"].as_u64(),
            vaults: v["vaults"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|m| VaultMemory {
                            last_unstake: m["last_unstake"].as_u64().unwrap_or(0),
                            unstaked: num(&m["unstaked"]),
                            unstaked_at: m["unstaked_at"].as_u64().unwrap_or(0),
                            last_steady: m["last_steady"].as_u64().unwrap_or(0),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn vault(&mut self, id: u32) -> &mut VaultMemory {
        let i = id as usize;
        if self.vaults.len() <= i {
            self.vaults.resize(i + 1, VaultMemory::default());
        }
        &mut self.vaults[i]
    }

    /// Records an action the chain accepted.
    pub fn apply(&mut self, action: &Action, now: u64) {
        match *action {
            Action::Unstake(v, amount) => {
                let m = self.vault(v);
                m.last_unstake = now;
                m.unstaked = m.unstaked.saturating_add(amount);
                m.unstaked_at = now;
            }
            Action::Withdraw(v, amount) => {
                let m = self.vault(v);
                m.unstaked = m.unstaked.saturating_sub(amount);
            }
            Action::Sync(_) | Action::Place(..) => {}
        }
    }

    /// Records that a vault's steady withdrawal of the grid line at `line` was run or skipped.
    pub fn steady_line(&mut self, vault: u32, line: u64) {
        self.vault(vault).last_steady = line;
    }

    pub fn settled(&mut self, now: u64, params: &Params) {
        self.last_slot = slot(now, params);
        self.activity = 0;
    }
}

fn slot(now: u64, params: &Params) -> u64 {
    if params.settlement_period_ns == 0 {
        now
    } else {
        now / params.settlement_period_ns
    }
}

pub struct Plan {
    pub actions: Vec<Action>,
    /// A settlement ran (its moves are among the actions): the caller records it.
    pub settled: bool,
    /// Grid lines of steady withdrawals reached, run (an `Unstake` among the actions) or skipped: the caller records
    /// them with `Memory::steady_line`, whatever the chain answers, so a line is never run late.
    pub steady: Vec<(u32, u64)>,
}

pub fn plan(params: &Params, now: u64, config: &ConfigInfo, vaults: &[VaultInfo], memory: &Memory, demand: &[u128]) -> Plan {
    let mut actions = Vec::new();
    let mut steady = Vec::new();
    let none = VaultMemory::default();
    let settle_now = slot(now, params) > memory.last_slot && memory.activity >= params.min_active;
    let may_place = !config.escape_open && now >= config.admin_pending_until;
    let mut settled = false;
    for (i, v) in vaults.iter().enumerate() {
        let id = i as u32;
        if v.busy {
            continue;
        }
        let m = memory.vaults.get(i).unwrap_or(&none);
        if (v.total_shares > 0 || v.placed > 0) && now >= v.synced_at.saturating_add(params.sync_every_ns) {
            actions.push(Action::Sync(id));
        }
        // An open vault is the contract's to empty: the agent's own amounts are refused there.
        if v.open {
            continue;
        }
        if m.unstaked > 0 && now >= m.unstaked_at.saturating_add(params.unbond_wait_ns) {
            actions.push(Action::Withdraw(id, m.unstaked));
        }
        let may_unstake = v.placed > 0 && (m.last_unstake == 0 || now >= m.last_unstake.saturating_add(UNSTAKE_INTERVAL_NS));
        let mut unstaking = false;
        if settle_now {
            let assets = v.liquid.saturating_add(v.placed);
            let target = (assets / 100 * u128::from(params.reserve_percent.min(100))).saturating_add(demand.get(i).copied().unwrap_or(0));
            let coming = v.liquid.saturating_add(v.withdrawing).saturating_add(m.unstaked);
            if v.liquid > target.saturating_add(params.min_move) && may_place && !v.frozen {
                let amount = (v.liquid - target).min(v.hourly_cap);
                if amount >= params.min_move {
                    actions.push(Action::Place(id, amount));
                    settled = true;
                }
            } else if coming < target && may_unstake {
                let amount = (target - coming).min(v.placed);
                if amount >= params.min_move {
                    actions.push(Action::Unstake(id, amount));
                    unstaking = true;
                    settled = true;
                }
            }
        }
        if params.steady_period_ns > 0 && params.steady_amount > 0 {
            let line = now / params.steady_period_ns * params.steady_period_ns;
            if line / params.steady_period_ns > m.last_steady / params.steady_period_ns {
                // On its line, or skipped: never late, never moved by a settlement.
                steady.push((id, line));
                if now < line.saturating_add(STEADY_SLACK_NS) && !unstaking && may_unstake && v.placed >= params.steady_amount {
                    actions.push(Action::Unstake(id, params.steady_amount));
                }
            }
        }
    }
    // The contract counts only the agent's syncs, placements and paid exits as activity, never an issue, entry or
    // leave. Once half the escape delay has passed without one, a sync of any free vault, even an empty one, tells the
    // contract the agent is there; it also closes an escape the agent's own silence opened.
    let active = actions.iter().any(|a| matches!(a, Action::Sync(_) | Action::Place(..)));
    if !active && now >= config.last_agent_call.saturating_add(config.escape_delay_ns / 2) {
        if let Some(id) = vaults.iter().position(|v| !v.busy && v.staking) {
            actions.push(Action::Sync(id as u32));
        }
    }
    Plan { actions, settled: settled || (settle_now && params.settlement_period_ns > 0), steady }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
    const HOUR: u64 = 3_600_000_000_000;

    fn config() -> ConfigInfo {
        ConfigInfo {
            agent: "agent.test".into(),
            network: "sandbox".into(),
            vault_count: 1,
            escape_open: false,
            // Recent activity: the keep-alive sync stays out of the tests that are not about it.
            last_agent_call: u64::MAX / 2,
            admin_pending_until: 0,
            escape_delay_ns: 7 * 24 * HOUR,
        }
    }

    fn vault(liquid: u128, placed: u128) -> VaultInfo {
        VaultInfo {
            tiers: vec![],
            liquid,
            placed,
            withdrawing: 0,
            total_shares: 1,
            share_price: 1,
            synced_at: 100 * HOUR,
            max_assets: u128::MAX,
            hourly_cap: 1_000 * NEAR,
            frozen: false,
            busy: false,
            requests: 0,
            open: false,
            staking: true,
        }
    }

    fn params() -> Params {
        Params { reserve_percent: 20, settlement_period_ns: HOUR / 2, min_active: 3, ..Params::default() }
    }

    #[test]
    fn money_moves_only_at_a_settlement_with_enough_activity() {
        let now = 100 * HOUR + 1;
        let memory = Memory { last_slot: slot(now, &params()) - 1, activity: 2, vaults: vec![], last_window: None };
        let plan_ = plan(&params(), now, &config(), &[vault(100 * NEAR, 0)], &memory, &[]);
        assert!(plan_.actions.is_empty(), "two entries are fewer than the threshold");
        let memory = Memory { activity: 3, ..memory };
        let plan_ = plan(&params(), now, &config(), &[vault(100 * NEAR, 0)], &memory, &[]);
        assert_eq!(plan_.actions, vec![Action::Place(0, 80 * NEAR)], "the reserve of 20 % stays liquid");
        assert!(plan_.settled);
        let done = Memory { last_slot: slot(now, &params()), activity: 3, vaults: vec![], last_window: None };
        assert!(plan(&params(), now, &config(), &[vault(100 * NEAR, 0)], &done, &[]).actions.is_empty(), "once per period");
    }

    #[test]
    fn a_short_reserve_is_refilled_once_per_unstake_interval() {
        let now = 100 * HOUR + 1;
        let memory = Memory { last_slot: 0, activity: 3, vaults: vec![], last_window: None };
        let plan_ = plan(&params(), now, &config(), &[vault(5 * NEAR, 95 * NEAR)], &memory, &[]);
        assert_eq!(plan_.actions, vec![Action::Unstake(0, 15 * NEAR)]);
        let recent = Memory { vaults: vec![VaultMemory { last_unstake: now - HOUR, ..Default::default() }], ..memory.clone() };
        assert!(plan(&params(), now, &config(), &[vault(5 * NEAR, 95 * NEAR)], &recent, &[]).actions.is_empty());
        let waiting = Memory { vaults: vec![VaultMemory { unstaked: 15 * NEAR, unstaked_at: now - HOUR, last_unstake: now - HOUR, last_steady: 0 }], ..memory };
        assert!(plan(&params(), now, &config(), &[vault(5 * NEAR, 95 * NEAR)], &waiting, &[]).actions.is_empty(), "already coming back");
    }

    #[test]
    fn unstaked_funds_are_withdrawn_after_the_unbonding_wait() {
        let p = Params::default();
        let now = 100 * HOUR;
        let m = Memory { vaults: vec![VaultMemory { unstaked: 7 * NEAR, unstaked_at: now - p.unbond_wait_ns, last_unstake: 1, last_steady: 0 }], ..Default::default() };
        assert!(plan(&p, now, &config(), &[vault(0, 10 * NEAR)], &m, &[]).actions.contains(&Action::Withdraw(0, 7 * NEAR)));
        let early = Memory { vaults: vec![VaultMemory { unstaked_at: now - p.unbond_wait_ns + 1, ..m.vaults[0].clone() }], ..m };
        assert!(!plan(&p, now, &config(), &[vault(0, 10 * NEAR)], &early, &[]).actions.iter().any(|a| matches!(a, Action::Withdraw(..))));
    }

    #[test]
    fn nothing_is_placed_in_a_frozen_or_open_vault_or_while_an_announcement_waits() {
        let now = 100 * HOUR + 1;
        let memory = Memory { last_slot: 0, activity: 9, vaults: vec![], last_window: None };
        let mut frozen = vault(100 * NEAR, 0);
        frozen.frozen = true;
        assert!(plan(&params(), now, &config(), &[frozen], &memory, &[]).actions.is_empty());
        let mut open = vault(100 * NEAR, 0);
        open.open = true;
        assert!(plan(&params(), now, &config(), &[open], &memory, &[]).actions.is_empty());
        let pending = ConfigInfo { admin_pending_until: now + 1, ..config() };
        assert!(plan(&params(), now, &pending, &[vault(100 * NEAR, 0)], &memory, &[]).actions.is_empty());
        let mut busy = vault(100 * NEAR, 0);
        busy.busy = true;
        assert!(plan(&params(), now, &config(), &[busy], &memory, &[]).actions.is_empty());
    }

    #[test]
    fn placements_respect_the_hourly_cap() {
        let now = 100 * HOUR + 1;
        let mut v = vault(5_000 * NEAR, 0);
        v.hourly_cap = 300 * NEAR;
        let memory = Memory { last_slot: 0, activity: 9, vaults: vec![], last_window: None };
        assert_eq!(plan(&params(), now, &config(), &[v], &memory, &[]).actions, vec![Action::Place(0, 300 * NEAR)]);
    }

    const D: u64 = UNSTAKE_INTERVAL_NS;

    #[test]
    fn stale_vaults_are_synced_and_steady_withdrawals_run_on_their_own_pace() {
        let p = Params { steady_period_ns: D, steady_amount: 2 * NEAR, ..Params::default() };
        let now = 10 * D;
        let mut v = vault(0, 50 * NEAR);
        v.synced_at = now - p.sync_every_ns;
        let plan_ = plan(&p, now, &config(), &[v.clone()], &Memory::default(), &[]);
        assert_eq!(plan_.actions, vec![Action::Sync(0), Action::Unstake(0, 2 * NEAR)]);
        assert_eq!(plan_.steady, vec![(0, now)]);
        let m = Memory { vaults: vec![VaultMemory { last_steady: now, ..Default::default() }], ..Default::default() };
        assert_eq!(plan(&p, now + HOUR / 2, &config(), &[v], &m, &[]).actions, vec![Action::Sync(0)]);
    }

    #[test]
    fn a_steady_period_must_be_a_multiple_of_three_days() {
        assert!(Params { steady_period_ns: 6 * HOUR, ..Params::default() }.check().is_err());
        assert!(Params { steady_period_ns: D + HOUR, ..Params::default() }.check().is_err());
        assert!(Params { steady_period_ns: 2 * D, ..Params::default() }.check().is_ok());
        assert!(Params { steady_period_ns: 0, ..Params::default() }.check().is_ok(), "off");
        assert!(Params { reserve_percent: 101, ..Params::default() }.check().is_err());
    }

    #[test]
    fn a_steady_line_missed_or_blocked_by_a_settlement_is_skipped_not_run_late() {
        let p = Params { steady_period_ns: D, steady_amount: 2 * NEAR, min_active: 1_000, ..Params::default() };
        let mut v = vault(0, 50 * NEAR);
        v.synced_at = 1_000 * D;
        let m = Memory { vaults: vec![VaultMemory { last_steady: 10 * D, ..Default::default() }], ..Default::default() };
        // The agent was down at the line: two hours late, the line is consumed without an unstake.
        let late = plan(&p, 11 * D + 2 * HOUR, &config(), &[v.clone()], &m, &[]);
        assert!(late.actions.is_empty());
        assert_eq!(late.steady, vec![(0, 11 * D)]);
        // A settlement unstaked a day before the line: the contract would refuse, so the line is skipped.
        let settled = Memory { vaults: vec![VaultMemory { last_steady: 10 * D, last_unstake: 11 * D - D / 3, ..Default::default() }], ..Default::default() };
        let blocked = plan(&p, 11 * D, &config(), &[v.clone()], &settled, &[]);
        assert!(blocked.actions.is_empty());
        assert_eq!(blocked.steady, vec![(0, 11 * D)]);
        let next = Memory { vaults: vec![VaultMemory { last_steady: 11 * D, last_unstake: 11 * D - D / 3, ..Default::default() }], ..Default::default() };
        assert_eq!(plan(&p, 12 * D, &config(), &[v], &next, &[]).actions, vec![Action::Unstake(0, 2 * NEAR)], "the next line runs");
    }

    #[test]
    fn queued_leaves_are_added_to_the_reserve() {
        let now = 100 * HOUR + 1;
        let memory = Memory { last_slot: 0, activity: 3, vaults: vec![], last_window: None };
        let plan_ = plan(&params(), now, &config(), &[vault(100 * NEAR, 0)], &memory, &[30 * NEAR]);
        assert_eq!(plan_.actions, vec![Action::Place(0, 50 * NEAR)], "20 % reserve plus 30 NEAR of waiting leaves stay liquid");
    }

    #[test]
    fn steady_withdrawals_follow_a_fixed_grid() {
        let p = Params { steady_period_ns: D, steady_amount: 2 * NEAR, min_active: 1_000, ..Params::default() };
        let mut v = vault(0, 50 * NEAR);
        v.synced_at = 1_000 * D;
        let m = Memory { vaults: vec![VaultMemory { last_steady: 10 * D, last_unstake: 0, ..Default::default() }], ..Default::default() };
        assert!(plan(&p, 10 * D + 5 * HOUR, &config(), &[v.clone()], &m, &[]).actions.is_empty(), "between two lines");
        assert_eq!(plan(&p, 11 * D, &config(), &[v], &m, &[]).actions, vec![Action::Unstake(0, 2 * NEAR)], "on the line");
    }

    #[test]
    fn the_agent_tells_the_contract_it_is_there_even_with_nothing_placed() {
        let empty = VaultInfo { total_shares: 0, ..vault(0, 0) };
        let delay = config().escape_delay_ns;
        let quiet = Memory { last_slot: u64::MAX, ..Memory::default() };
        let at = |now: u64, last: u64| plan(&params(), now, &ConfigInfo { last_agent_call: last, ..config() }, &[empty.clone()], &quiet, &[]).actions;
        assert!(at(1_000 * HOUR, 1_000 * HOUR - HOUR).is_empty(), "nothing to do yet");
        assert_eq!(at(1_000 * HOUR, 1_000 * HOUR - delay / 2), vec![Action::Sync(0)], "half the escape delay without activity");
        // Silent past the delay: the escape is open, and the agent's sync closes it.
        let open = ConfigInfo { last_agent_call: 0, escape_open: true, ..config() };
        assert_eq!(plan(&params(), 1_000 * HOUR, &open, &[empty.clone()], &quiet, &[]).actions, vec![Action::Sync(0)]);
        let busy = VaultInfo { busy: true, ..empty.clone() };
        assert!(plan(&params(), 1_000 * HOUR, &open, &[busy], &quiet, &[]).actions.is_empty(), "a busy vault cannot be synced");
        let lending = VaultInfo { staking: false, ..empty.clone() };
        assert_eq!(plan(&params(), 1_000 * HOUR, &open, &[lending, empty], &quiet, &[]).actions, vec![Action::Sync(1)], "only a staking vault syncs");
    }

    #[test]
    fn the_defaults_are_not_zero() {
        let d = Params::default();
        assert!(d.reserve_percent > 0 && d.settlement_period_ns > 0 && d.min_active > 0);
    }

    #[test]
    fn memory_round_trips() {
        let m = Memory { last_slot: 3, activity: 4, vaults: vec![VaultMemory { last_unstake: 1, unstaked: 2, unstaked_at: 3, last_steady: 4 }], last_window: Some(5) };
        assert_eq!(Memory::from_json(&m.to_json()), m);
    }
}
