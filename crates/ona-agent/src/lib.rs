//! `ona-agent`: the program that acts on `ona-pool` for its users. It holds the blind-signing keys of the cash notes
//! and of each vault's share notes, signs notes only after the contract has done what they stand for, and calls the
//! contract with the agent's account key: `issue_cash`, `enter`, `leave`, `pay_exit` for users, and `place`, `sync`,
//! `unstake`, `withdraw` on its own schedule (`planner`).
//!
//! It never holds users' money: the contract does, and pays exits only to the accounts that deposited. What the agent
//! can do wrong is limited to the contract's rules (hourly caps, delays, the escape after seven days of silence).
//!
//! Never run against a real chain yet. Not in an enclave yet: whoever runs it sees which note asks for which vault.

#![forbid(unsafe_code)]

pub mod api;
pub mod chain;
pub mod keys;
pub mod nep413;
pub mod planner;
pub mod service;
pub mod store;

/// Ties a store to one set of keys: a store made for other keys is refused.
pub fn store_binding(keys: &keys::AgentKeys, pool: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pool.as_bytes());
    for pk in keys.cash_public() {
        h.update(pk);
    }
    for v in 0..keys.vaults.len() {
        for pk in keys.vault_public(v).unwrap_or_default() {
            h.update(pk);
        }
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
