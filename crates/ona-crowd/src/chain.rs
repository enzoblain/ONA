//! Plays a public timeline on a chain: in memory for tests, or on NEAR through [`crate::near`].

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};

use crate::{Config, EventKind, FakeUser, PublicEvent, Simulation, Vault};

/// The operations the timeline needs. Amounts are units of the asset.
pub trait Chain {
    /// Sends `units` to `account`, plus what its own `transactions`, carrying `notes` mint tokens in
    /// all, will cost.
    fn fund(&mut self, account: &str, units: u64, transactions: u64, notes: u64) -> Result<()>;
    fn deposit(&mut self, user: &FakeUser, denomination: u64, count: u32) -> Result<()>;
    fn place(&mut self, vault: &Vault, denomination: u64, count: u32) -> Result<()>;
    fn withdraw(&mut self, vault: &Vault, denomination: u64, count: u32) -> Result<()>;
    fn pay(&mut self, to: &str, denomination: u64) -> Result<()>;
}

/// Checks that an event only carries whole notes of a listed denomination, as every event must.
pub fn check_event(config: &Config, event: &PublicEvent) -> Result<()> {
    if !config.denominations.contains(&event.denomination) {
        bail!("event {} uses an unlisted denomination {}", event.id, event.denomination);
    }
    if event.count == 0 || u64::from(event.count).checked_mul(event.denomination) != Some(event.amount) {
        bail!("event {} amount is not a whole number of notes", event.id);
    }
    if event.kind == EventKind::ExitPayment && event.count != 1 {
        bail!("event {} pays more than one note at once", event.id);
    }
    if event.kind == EventKind::Deposit && !event.count.is_power_of_two() {
        bail!("event {} deposits a count the mint refuses", event.id);
    }
    Ok(())
}

/// Exits only go back to an account that deposited, and never above what it deposited at that
/// moment. The cap is deposits plus gains; the simulation models no gains, so it is the deposits.
pub fn check_exit_caps(timeline: &[PublicEvent]) -> Result<()> {
    let mut balance: BTreeMap<&str, u64> = BTreeMap::new();
    for e in timeline {
        match e.kind {
            EventKind::Deposit => *balance.entry(e.from.as_str()).or_default() += e.amount,
            EventKind::ExitPayment => {
                let held = balance.get_mut(e.to.as_str()).ok_or_else(|| anyhow!("event {} pays an account that never deposited", e.id))?;
                *held = held.checked_sub(e.amount).ok_or_else(|| anyhow!("event {} pays more than the account deposited", e.id))?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Funds each fake user with what it deposits, then plays the events in order. `wait` receives the
/// seconds between two events, so a caller can pace a real run. Stops at the first error.
pub fn execute(sim: &Simulation, config: &Config, chain: &mut dyn Chain, wait: &mut dyn FnMut(u64)) -> Result<()> {
    for event in &sim.timeline {
        check_event(config, event)?;
    }
    check_exit_caps(&sim.timeline)?;
    let by_account: BTreeMap<String, &FakeUser> = sim.users.iter().map(|u| (u.account(), u)).collect();
    let mut owed: BTreeMap<&str, (u64, u64, u64)> = BTreeMap::new();
    for e in sim.timeline.iter().filter(|e| e.kind == EventKind::Deposit) {
        let entry = owed.entry(e.from.as_str()).or_default();
        entry.0 += e.amount;
        entry.1 += 1;
        entry.2 += u64::from(e.count);
    }
    for (account, (units, transactions, notes)) in owed {
        chain.fund(account, units, transactions, notes)?;
    }

    let vault = |contract: &str| -> Result<&Vault> {
        config.vaults.iter().find(|v| v.contract == contract).ok_or_else(|| anyhow!("unknown vault {contract}"))
    };
    let mut now = 0;
    for e in &sim.timeline {
        wait(e.at_secs.saturating_sub(now));
        now = now.max(e.at_secs);
        match e.kind {
            EventKind::Deposit => {
                let user = by_account.get(&e.from).ok_or_else(|| anyhow!("deposit from an unknown user"))?;
                chain.deposit(user, e.denomination, e.count)?;
            }
            EventKind::Placement => chain.place(vault(&e.to)?, e.denomination, e.count)?,
            EventKind::Withdrawal => chain.withdraw(vault(&e.from)?, e.denomination, e.count)?,
            EventKind::ExitPayment => chain.pay(&e.to, e.denomination)?,
        }
    }
    Ok(())
}

/// A chain in memory. The mint and the pool are one reserve: deposits fill it, placements move
/// funds to a vault, withdrawals bring them back, exit payments leave it. Any operation that would
/// overdraw an account fails.
#[derive(Debug, Default)]
pub struct MemoryChain {
    pub balances: BTreeMap<String, u64>,
    pub reserve: u64,
    pub vaults: BTreeMap<String, u64>,
    pub operations: usize,
}

fn take(from: &mut u64, amount: u64, what: &str) -> Result<()> {
    *from = from.checked_sub(amount).ok_or_else(|| anyhow!("{what} does not hold {amount}"))?;
    Ok(())
}

impl Chain for MemoryChain {
    fn fund(&mut self, account: &str, units: u64, _transactions: u64, _notes: u64) -> Result<()> {
        *self.balances.entry(account.to_string()).or_default() += units;
        self.operations += 1;
        Ok(())
    }

    fn deposit(&mut self, user: &FakeUser, denomination: u64, count: u32) -> Result<()> {
        let amount = denomination * u64::from(count);
        take(self.balances.entry(user.account()).or_default(), amount, "user")?;
        self.reserve += amount;
        self.operations += 1;
        Ok(())
    }

    fn place(&mut self, vault: &Vault, denomination: u64, count: u32) -> Result<()> {
        let amount = denomination * u64::from(count);
        take(&mut self.reserve, amount, "reserve")?;
        *self.vaults.entry(vault.contract.clone()).or_default() += amount;
        self.operations += 1;
        Ok(())
    }

    fn withdraw(&mut self, vault: &Vault, denomination: u64, count: u32) -> Result<()> {
        let amount = denomination * u64::from(count);
        take(self.vaults.entry(vault.contract.clone()).or_default(), amount, "vault")?;
        self.reserve += amount;
        self.operations += 1;
        Ok(())
    }

    fn pay(&mut self, to: &str, denomination: u64) -> Result<()> {
        take(&mut self.reserve, denomination, "reserve")?;
        *self.balances.entry(to.to_string()).or_default() += denomination;
        self.operations += 1;
        Ok(())
    }
}
