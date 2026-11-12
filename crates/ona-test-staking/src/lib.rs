//! `ona-test-staking`: a **test stand-in** for a NEAR staking pool, deployed only by `ona-sandbox-pool` on a local node so
//! that `ona-pool` can place, unstake and withdraw against a real NEAR runtime. Never deploy it anywhere else: it
//! stakes nothing with a validator and pays no reward unless a test asks (`add_reward`).
//!
//! Its methods carry the names `ona-pool` calls (`deposit_and_stake`, `unstake {amount}`, `withdraw {amount}`,
//! `get_account_staked_balance`, `get_account_unstaked_balance`, `get_account_total_balance`, each view taking
//! `{account_id}`), which come from the standard staking pool of `near/core-contracts` as recalled: not verified
//! against its source. It applies the rules of the strict mock in `ona-pool`'s tests:
//! - `unstake` moves at most what is staked;
//! - `withdraw` returns at most what is unstaked, only once `lock_secs` of block time have passed since the account's
//!   last `unstake`, and each `unstake` pushes that moment back for everything already unstaked;
//! - a refused call panics, so the caller's callback sees a failed promise.
#![forbid(unsafe_code)]

use near_sdk::collections::LookupMap;
use near_sdk::json_types::U128;
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};

#[near(serializers = [borsh])]
#[derive(Default, Clone)]
pub struct Account {
    staked: u128,
    unstaked: u128,
    /// Block time from which the unstaked funds may be withdrawn.
    unlock_at: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TestStaking {
    lock_ns: u64,
    accounts: LookupMap<AccountId, Account>,
}

#[near]
impl TestStaking {
    /// `lock_secs`: how long unstaked funds stay locked, a stand-in for the epochs a real pool waits.
    #[init]
    pub fn new(lock_secs: u64) -> Self {
        Self { lock_ns: lock_secs.saturating_mul(1_000_000_000), accounts: LookupMap::new(b"a".to_vec()) }
    }

    fn get(&self, account: &AccountId) -> Account {
        self.accounts.get(account).unwrap_or_default()
    }

    /// Stakes everything attached for the caller.
    #[payable]
    pub fn deposit_and_stake(&mut self) {
        let account = env::predecessor_account_id();
        let amount = env::attached_deposit().as_yoctonear();
        require!(amount > 0, "attach the amount to stake");
        let mut a = self.get(&account);
        a.staked = a.staked.checked_add(amount).unwrap_or_else(|| env::panic_str("too much"));
        self.accounts.insert(&account, &a);
    }

    pub fn unstake(&mut self, amount: U128) {
        let account = env::predecessor_account_id();
        let mut a = self.get(&account);
        require!(amount.0 > 0, "amount must be positive");
        require!(amount.0 <= a.staked, "not enough staked balance to unstake");
        a.staked -= amount.0;
        a.unstaked += amount.0;
        a.unlock_at = env::block_timestamp().saturating_add(self.lock_ns);
        self.accounts.insert(&account, &a);
    }

    /// Sends `amount` of the caller's unstaked funds back to the caller.
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        let account = env::predecessor_account_id();
        let mut a = self.get(&account);
        require!(amount.0 > 0, "amount must be positive");
        require!(amount.0 <= a.unstaked, "not enough unstaked balance to withdraw");
        require!(env::block_timestamp() >= a.unlock_at, "the unstaked balance is not yet available");
        a.unstaked -= amount.0;
        self.accounts.insert(&account, &a);
        Promise::new(account).transfer(NearToken::from_yoctonear(amount.0))
    }

    /// Test only: adds what is attached to `account_id`'s staked balance, as a reward would.
    #[payable]
    pub fn add_reward(&mut self, account_id: AccountId) {
        let mut a = self.get(&account_id);
        a.staked = a.staked.checked_add(env::attached_deposit().as_yoctonear()).unwrap_or_else(|| env::panic_str("too much"));
        self.accounts.insert(&account_id, &a);
    }

    pub fn get_account_staked_balance(&self, account_id: AccountId) -> U128 {
        U128(self.get(&account_id).staked)
    }

    pub fn get_account_unstaked_balance(&self, account_id: AccountId) -> U128 {
        U128(self.get(&account_id).unstaked)
    }

    pub fn get_account_total_balance(&self, account_id: AccountId) -> U128 {
        let a = self.get(&account_id);
        U128(a.staked.saturating_add(a.unstaked))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    const SECOND: u64 = 1_000_000_000;

    fn at(time: u64, deposit: u128) {
        let mut ctx = VMContextBuilder::new();
        ctx.predecessor_account_id(accounts(1)).block_timestamp(time).attached_deposit(NearToken::from_yoctonear(deposit));
        testing_env!(ctx.build());
    }

    fn staked() -> TestStaking {
        at(1, 0);
        let mut s = TestStaking::new(60);
        at(1, 100);
        s.deposit_and_stake();
        s
    }

    #[test]
    fn balances_follow_stake_unstake_and_withdraw() {
        let mut s = staked();
        at(10 * SECOND, 0);
        s.unstake(U128(40));
        assert_eq!((s.get_account_staked_balance(accounts(1)).0, s.get_account_unstaked_balance(accounts(1)).0), (60, 40));
        assert_eq!(s.get_account_total_balance(accounts(1)).0, 100);
        at(70 * SECOND, 0);
        let _ = s.withdraw(U128(40));
        assert_eq!(s.get_account_total_balance(accounts(1)).0, 60);
        at(70 * SECOND, 5);
        s.add_reward(accounts(1));
        assert_eq!(s.get_account_staked_balance(accounts(1)).0, 65);
    }

    #[test]
    #[should_panic(expected = "not enough staked balance")]
    fn no_unstake_above_the_staked_balance() {
        let mut s = staked();
        s.unstake(U128(101));
    }

    #[test]
    #[should_panic(expected = "not enough unstaked balance")]
    fn no_withdraw_above_the_unstaked_balance() {
        let mut s = staked();
        s.unstake(U128(10));
        at(100 * SECOND, 0);
        let _ = s.withdraw(U128(11));
    }

    #[test]
    #[should_panic(expected = "not yet available")]
    fn no_withdraw_before_the_lock_ends() {
        let mut s = staked();
        at(10 * SECOND, 0);
        s.unstake(U128(10));
        at(69 * SECOND, 0);
        let _ = s.withdraw(U128(10));
    }

    #[test]
    #[should_panic(expected = "not yet available")]
    fn each_unstake_pushes_the_lock_back() {
        let mut s = staked();
        at(10 * SECOND, 0);
        s.unstake(U128(10));
        at(65 * SECOND, 0);
        s.unstake(U128(10));
        at(80 * SECOND, 0);
        let _ = s.withdraw(U128(10));
    }
}
