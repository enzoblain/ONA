//! `ona-registry`: public anchors and published parameters. Holds no funds of its own. Draft, not audited.
//!
//! Who can do what:
//! - **One owner alone**, at once: revoke a value, or raise the incident level. Both only reduce trust, so an
//!   owner who cannot be reached, or whose key was stolen, cannot block an emergency. A value revoked this way
//!   can be restored by both owners (`Restore`, with notice), so one stolen key cannot remove a value for ever.
//! - **Both owners** (one proposes, the other confirms the exact same action): publish a value, which takes
//!   effect after `MIN_PUBLISH_DELAY_NS`; lower the incident level, change the aggregator, replace an owner or
//!   restore a value, which can only be confirmed `ADMIN_DELAY_NS` after the proposal. A proposal expires after
//!   `PROPOSAL_TTL_NS`, is checked again when confirmed, and only its proposer can cancel it.
//! - **One owner replacing a lost owner** (`propose_takeover`): confirmed by the same owner after
//!   `TAKEOVER_DELAY_NS`, unless the owner being replaced vetoes it before. The same path serves a thief: a
//!   stolen copy of one owner's key replaces the other owner if that owner does not veto in time, so owners
//!   must watch for takeovers. A stolen copy can also veto a takeover aimed at it: then only a new registry
//!   helps.
//! - Both owners can make an emergency revocation final with `Revoke`.
//! - **The aggregator**: anchor one root at most every `MIN_ANCHOR_INTERVAL_NS`.
//!
//! A revoked value never brings an older one back: once the newest value in force is revoked, the topic has no
//! value until a new one is published, with its notice period. A publication is refused while another one on
//! the same topic is still waiting for its date, so no value can sit hidden behind another. An older value
//! that was never revoked can be published again, as a new entry with its own notice period.
//!
//! Storage: `anchor` and `propose` are payable. The caller pays the storage it adds, and the excess is
//! refunded, so nobody can drain the contract's balance by writing to it.

use near_sdk::collections::{LookupMap, Vector};
use near_sdk::json_types::{Base64VecU8, U64};
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};

const HOUR_NS: u64 = 3_600_000_000_000;
const DAY_NS: u64 = 24 * HOUR_NS;

pub const MIN_PUBLISH_DELAY_NS: u64 = 7 * DAY_NS;
/// A value cannot be scheduled further ahead than this, so a wrong unit cannot block a topic for ever.
pub const MAX_PUBLISH_AHEAD_NS: u64 = 90 * DAY_NS;
/// Notice before a two-owner change of the incident level (downwards), the aggregator or an owner.
pub const ADMIN_DELAY_NS: u64 = 7 * DAY_NS;
/// A proposal not confirmed within this time can no longer be confirmed.
pub const PROPOSAL_TTL_NS: u64 = 30 * DAY_NS;
/// Wait before one owner alone can replace the other, who may veto meanwhile.
pub const TAKEOVER_DELAY_NS: u64 = 30 * DAY_NS;
pub const TAKEOVER_TTL_NS: u64 = 60 * DAY_NS;
/// The aggregator anchors once an hour; this floor leaves room for a late anchor without allowing a flood.
pub const MIN_ANCHOR_INTERVAL_NS: u64 = 30 * 60 * 1_000_000_000;
pub const MAX_PENDING_PER_OWNER: u32 = 4;
pub const MAX_INCIDENT_LEVEL: u8 = 3;
pub const MAX_TOPIC_LEN: usize = 32;
pub const MAX_VALUE_LEN: usize = 256;

#[near(serializers = [borsh, json])]
#[derive(Clone, PartialEq, Debug)]
pub enum RegistryAction {
    Publish { topic: String, value: Base64VecU8, valid_from: U64 },
    Revoke { topic: String, value: Base64VecU8 },
    SetIncident { level: u8 },
    SetAggregator { aggregator: AccountId },
    ChangeOwner { old: AccountId, new: AccountId },
    /// Undoes a revocation made by one owner alone.
    Restore { topic: String, value: Base64VecU8 },
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Anchor {
    pub seq: U64,
    pub root: Base64VecU8,
    pub timestamp: U64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub value: Base64VecU8,
    pub valid_from: U64,
    /// When it was revoked. Revoked before `valid_from` means cancelled: it never took effect.
    pub revoked_at: Option<U64>,
    /// Revoked by one owner alone, so both owners may restore it.
    pub emergency: bool,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Proposal {
    pub action: RegistryAction,
    pub proposer: AccountId,
    pub created_at: U64,
    /// A takeover: confirmed by its own proposer after `TAKEOVER_DELAY_NS`.
    pub solo: bool,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Registry {
    owners: [AccountId; 2],
    aggregator: AccountId,
    incident_level: u8,
    next_proposal: u64,
    proposals: LookupMap<u64, Proposal>,
    /// Pending proposal ids of each owner.
    pending: [Vec<u64>; 2],
    anchors: Vector<Anchor>,
    entries: LookupMap<String, Vec<Entry>>,
}

#[near]
impl Registry {
    #[init]
    pub fn new(owners: [AccountId; 2], aggregator: AccountId) -> Self {
        require!(owners[0] != owners[1], "the two owners must differ");
        require!(!owners.contains(&aggregator), "the aggregator cannot be an owner");
        Self {
            owners,
            aggregator,
            incident_level: 0,
            next_proposal: 0,
            proposals: LookupMap::new(b"p".to_vec()),
            pending: [Vec::new(), Vec::new()],
            anchors: Vector::new(b"a".to_vec()),
            entries: LookupMap::new(b"e".to_vec()),
        }
    }

    #[payable]
    pub fn anchor(&mut self, root: Base64VecU8) -> U64 {
        require!(env::predecessor_account_id() == self.aggregator, "only the aggregator can anchor");
        require!(root.0.len() == 32, "root must be 32 bytes");
        let now = env::block_timestamp();
        if let Some(last) = self.latest_anchor() {
            require!(now >= last.timestamp.0.saturating_add(MIN_ANCHOR_INTERVAL_NS), "anchored too recently");
        }
        let before = env::storage_usage();
        let seq = U64(self.anchors.len());
        self.anchors.push(&Anchor { seq, root, timestamp: U64(now) });
        charge_storage(before);
        seq
    }

    #[payable]
    pub fn propose(&mut self, action: RegistryAction) -> U64 {
        let proposer = self.require_owner();
        self.validate(&action);
        self.add_proposal(action, proposer, false)
    }

    /// One owner proposes to replace the other, who is lost. Confirmed by the same owner after
    /// `TAKEOVER_DELAY_NS`; the owner being replaced can veto it until then.
    #[payable]
    pub fn propose_takeover(&mut self, new: AccountId) -> U64 {
        let proposer = self.require_owner();
        let other = self.owners[1 - self.owner_slot(&proposer)].clone();
        let action = RegistryAction::ChangeOwner { old: other, new };
        self.validate(&action);
        self.add_proposal(action, proposer, true)
    }

    /// Applies a proposal, restating the exact action so nobody confirms a number without knowing what it
    /// does. The action is checked again against the current state. A normal proposal is confirmed by the
    /// other owner; a takeover by its own proposer, once its delay is over.
    pub fn confirm(&mut self, id: U64, action: RegistryAction) {
        let confirmer = self.require_owner();
        let proposal = self.proposals.get(&id.0).unwrap_or_else(|| env::panic_str("unknown proposal"));
        require!(self.owners.contains(&proposal.proposer), "its proposer is no longer an owner");
        require!(proposal.action == action, "the action differs from the proposal");
        let now = env::block_timestamp();
        let created = proposal.created_at.0;
        if proposal.solo {
            require!(confirmer == proposal.proposer, "a takeover is confirmed by its proposer");
            require!(now < created.saturating_add(TAKEOVER_TTL_NS), "the proposal has expired");
            require!(now >= created.saturating_add(TAKEOVER_DELAY_NS), "the takeover delay is not over");
        } else {
            require!(confirmer != proposal.proposer, "the other owner must confirm");
            require!(now < created.saturating_add(PROPOSAL_TTL_NS), "the proposal has expired");
            if self.needs_notice(&proposal.action) {
                require!(now >= created.saturating_add(ADMIN_DELAY_NS), "the notice period is not over");
            }
        }
        self.validate(&proposal.action);
        self.remove_proposal(id.0, &proposal);
        self.apply(proposal.action, false);
    }

    /// Only the proposer can withdraw a proposal.
    pub fn cancel(&mut self, id: U64) {
        let caller = self.require_owner();
        let proposal = self.proposals.get(&id.0).unwrap_or_else(|| env::panic_str("unknown proposal"));
        require!(caller == proposal.proposer, "only the proposer can cancel");
        self.remove_proposal(id.0, &proposal);
    }

    /// The owner a takeover would replace refuses it.
    pub fn veto(&mut self, id: U64) {
        let caller = self.require_owner();
        let proposal = self.proposals.get(&id.0).unwrap_or_else(|| env::panic_str("unknown proposal"));
        require!(proposal.solo && caller != proposal.proposer, "only the owner being replaced can veto");
        self.remove_proposal(id.0, &proposal);
    }

    /// One owner alone: revoke a value, or raise the incident level. Nothing else.
    pub fn emergency(&mut self, action: RegistryAction) {
        self.require_owner();
        self.validate(&action);
        match &action {
            RegistryAction::Revoke { .. } => {}
            RegistryAction::SetIncident { level } => {
                require!(*level > self.incident_level, "one owner can only raise the incident level")
            }
            _ => env::panic_str("this action needs both owners"),
        }
        self.apply(action, true);
    }

    pub fn get_proposal(&self, id: U64) -> Option<Proposal> {
        self.proposals.get(&id.0)
    }

    pub fn get_anchor(&self, seq: U64) -> Option<Anchor> {
        self.anchors.get(seq.0)
    }

    pub fn latest_anchor(&self) -> Option<Anchor> {
        self.anchors.len().checked_sub(1).and_then(|last| self.anchors.get(last))
    }

    pub fn incident_level(&self) -> u8 {
        self.incident_level
    }

    pub fn aggregator(&self) -> AccountId {
        self.aggregator.clone()
    }

    pub fn owners(&self) -> [AccountId; 2] {
        self.owners.clone()
    }

    /// The value in force now: the newest one whose date has come, unless it was revoked. A value cancelled
    /// before its date is skipped; a value revoked once in force leaves the topic without a value.
    pub fn active(&self, topic: String) -> Option<Base64VecU8> {
        let now = env::block_timestamp();
        for entry in self.entries.get(&topic)?.into_iter().rev() {
            if entry.valid_from.0 > now {
                continue;
            }
            match entry.revoked_at {
                None => return Some(entry.value),
                Some(at) if at.0 < entry.valid_from.0 => continue,
                Some(_) => return None,
            }
        }
        None
    }

    /// Everything ever published on a topic, so a wallet can see scheduled changes.
    pub fn history(&self, topic: String) -> Vec<Entry> {
        self.entries.get(&topic).unwrap_or_default()
    }
}

/// The caller pays for the bytes this call added; whatever it attached beyond that goes back to it.
fn charge_storage(before: u64) {
    let added = env::storage_usage().saturating_sub(before);
    let cost = env::storage_byte_cost().as_yoctonear().saturating_mul(u128::from(added));
    let attached = env::attached_deposit().as_yoctonear();
    require!(attached >= cost, format!("attach at least {cost} yoctoNEAR for storage"));
    let refund = attached - cost;
    if refund > 0 {
        // A promise left unreturned is still scheduled when it is dropped.
        let _refund = Promise::new(env::predecessor_account_id()).transfer(NearToken::from_yoctonear(refund));
    }
}

impl Registry {
    fn require_owner(&self) -> AccountId {
        let caller = env::predecessor_account_id();
        require!(self.owners.contains(&caller), "only an owner can do this");
        caller
    }

    fn owner_slot(&self, owner: &AccountId) -> usize {
        usize::from(self.owners[1] == *owner)
    }

    fn add_proposal(&mut self, action: RegistryAction, proposer: AccountId, solo: bool) -> U64 {
        let slot = self.owner_slot(&proposer);
        // Expired proposals can no longer be confirmed: they are removed and stop counting.
        let now = env::block_timestamp();
        let ids = std::mem::take(&mut self.pending[slot]);
        for id in ids {
            let live = self.proposals.get(&id).is_some_and(|p| {
                let ttl = if p.solo { TAKEOVER_TTL_NS } else { PROPOSAL_TTL_NS };
                now < p.created_at.0.saturating_add(ttl)
            });
            if live {
                self.pending[slot].push(id);
            } else {
                self.proposals.remove(&id);
            }
        }
        require!((self.pending[slot].len() as u32) < MAX_PENDING_PER_OWNER, "too many pending proposals");
        let before = env::storage_usage();
        let id = self.next_proposal;
        self.next_proposal += 1;
        self.proposals.insert(&id, &Proposal { action, proposer, created_at: U64(env::block_timestamp()), solo });
        self.pending[slot].push(id);
        charge_storage(before);
        U64(id)
    }

    fn remove_proposal(&mut self, id: u64, proposal: &Proposal) {
        self.proposals.remove(&id);
        if self.owners.contains(&proposal.proposer) {
            let slot = self.owner_slot(&proposal.proposer);
            self.pending[slot].retain(|p| *p != id);
        }
    }

    fn needs_notice(&self, action: &RegistryAction) -> bool {
        match action {
            RegistryAction::SetIncident { level } => *level < self.incident_level,
            RegistryAction::SetAggregator { .. } | RegistryAction::ChangeOwner { .. } | RegistryAction::Restore { .. } => {
                true
            }
            RegistryAction::Publish { .. } | RegistryAction::Revoke { .. } => false,
        }
    }

    fn validate(&self, action: &RegistryAction) {
        let check_topic = |t: &str| {
            require!(
                !t.is_empty()
                    && t.len() <= MAX_TOPIC_LEN
                    && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'),
                "bad topic"
            )
        };
        match action {
            RegistryAction::Publish { topic, value, .. }
            | RegistryAction::Revoke { topic, value }
            | RegistryAction::Restore { topic, value } => {
                check_topic(topic);
                require!(!value.0.is_empty() && value.0.len() <= MAX_VALUE_LEN, "bad value");
            }
            RegistryAction::SetIncident { level } => {
                require!(*level <= MAX_INCIDENT_LEVEL, "bad incident level");
            }
            RegistryAction::SetAggregator { aggregator } => {
                require!(!self.owners.contains(aggregator), "the aggregator cannot be an owner");
            }
            RegistryAction::ChangeOwner { old, new } => {
                require!(self.owners.contains(old), "not an owner");
                require!(!self.owners.contains(new), "already an owner");
                require!(*new != self.aggregator, "the aggregator cannot be an owner");
            }
        }
    }

    fn apply(&mut self, action: RegistryAction, emergency: bool) {
        let now = env::block_timestamp();
        match action {
            RegistryAction::Publish { topic, value, valid_from } => {
                // Checked at confirmation: an old proposal must not shorten the notice period.
                require!(valid_from.0 >= now.saturating_add(MIN_PUBLISH_DELAY_NS), "valid_from is too soon");
                require!(valid_from.0 <= now.saturating_add(MAX_PUBLISH_AHEAD_NS), "valid_from is too far ahead");
                let mut list = self.entries.get(&topic).unwrap_or_default();
                require!(
                    !list.iter().any(|e| e.value == value && e.revoked_at.is_some()),
                    "this value was revoked and cannot come back"
                );
                if let Some(last) = list.last() {
                    require!(
                        last.valid_from.0 <= now || last.revoked_at.is_some(),
                        "another value on this topic is still pending"
                    );
                    require!(last.value != value || last.revoked_at.is_some(), "value already published");
                    require!(valid_from.0 > last.valid_from.0, "valid_from must increase");
                }
                list.push(Entry { value, valid_from, revoked_at: None, emergency: false });
                self.entries.insert(&topic, &list);
            }
            RegistryAction::Revoke { topic, value } => {
                let mut list = self.entries.get(&topic).unwrap_or_default();
                let mut found = false;
                for entry in list.iter_mut().filter(|e| e.value == value) {
                    if entry.revoked_at.is_none() {
                        entry.revoked_at = Some(U64(now));
                        entry.emergency = emergency;
                        found = true;
                    } else if entry.emergency && !emergency {
                        // Both owners confirm a revocation made by one: it becomes final.
                        entry.emergency = false;
                        found = true;
                    }
                }
                require!(found, "unknown value");
                self.entries.insert(&topic, &list);
            }
            RegistryAction::Restore { topic, value } => {
                let mut list = self.entries.get(&topic).unwrap_or_default();
                let mut found = false;
                for entry in list.iter_mut().filter(|e| e.value == value && e.emergency) {
                    entry.revoked_at = None;
                    entry.emergency = false;
                    found = true;
                }
                require!(found, "no value revoked by one owner to restore");
                self.entries.insert(&topic, &list);
            }
            RegistryAction::SetIncident { level } => self.incident_level = level,
            RegistryAction::SetAggregator { aggregator } => self.aggregator = aggregator,
            RegistryAction::ChangeOwner { old, new } => {
                let slot = self.owner_slot(&old);
                // The replaced owner's proposals go with it.
                for id in std::mem::take(&mut self.pending[slot]) {
                    self.proposals.remove(&id);
                }
                self.owners[slot] = new;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const DAY: u64 = DAY_NS;
    const DEPOSIT: NearToken = NearToken::from_millinear(10);

    fn acc(s: &str) -> AccountId {
        s.parse().unwrap()
    }

    fn ctx_with(who: &str, now: u64, deposit: NearToken) {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(acc(who))
            .block_timestamp(now)
            .attached_deposit(deposit)
            .storage_usage(10_000)
            .build());
    }

    fn ctx(who: &str, now: u64) {
        ctx_with(who, now, DEPOSIT);
    }

    fn registry() -> Registry {
        ctx("deployer.test", DAY);
        Registry::new([acc("a.test"), acc("b.test")], acc("agg.test"))
    }

    fn refused(f: impl FnOnce()) -> String {
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = catch_unwind(AssertUnwindSafe(f));
        std::panic::set_hook(hook);
        let e = r.expect_err("should be refused");
        e.downcast_ref::<String>().cloned().unwrap_or_default()
    }

    fn val(b: u8) -> Base64VecU8 {
        Base64VecU8(vec![b; 8])
    }

    fn publish(topic: &str, value: u8, from: u64) -> RegistryAction {
        RegistryAction::Publish { topic: topic.into(), value: val(value), valid_from: U64(from) }
    }

    fn revoke(topic: &str, value: u8) -> RegistryAction {
        RegistryAction::Revoke { topic: topic.into(), value: val(value) }
    }

    /// Proposed by a at `now`, confirmed by b at `confirm_at`.
    fn enact_at(r: &mut Registry, action: RegistryAction, now: u64, confirm_at: u64) {
        ctx("a.test", now);
        let id = r.propose(action.clone());
        ctx("b.test", confirm_at);
        r.confirm(id, action);
    }

    fn enact(r: &mut Registry, action: RegistryAction, now: u64) {
        enact_at(r, action, now, now);
    }

    #[test]
    fn owners_must_differ_and_exclude_the_aggregator() {
        ctx("deployer.test", DAY);
        assert!(refused(|| {
            Registry::new([acc("a.test"), acc("a.test")], acc("agg.test"));
        })
        .contains("must differ"));
        assert!(refused(|| {
            Registry::new([acc("a.test"), acc("b.test")], acc("a.test"));
        })
        .contains("cannot be an owner"));
    }

    #[test]
    fn anchors_are_append_only_and_restricted() {
        let mut r = registry();
        ctx("agg.test", 2 * DAY);
        assert_eq!(r.anchor(Base64VecU8(vec![1; 32])), U64(0));
        ctx("agg.test", 3 * DAY);
        assert_eq!(r.anchor(Base64VecU8(vec![2; 32])), U64(1));
        assert_eq!(r.get_anchor(U64(0)).unwrap().root, Base64VecU8(vec![1; 32]));
        let latest = r.latest_anchor().unwrap();
        assert_eq!((latest.seq, latest.timestamp), (U64(1), U64(3 * DAY)));

        ctx("agg.test", 4 * DAY);
        assert!(refused(|| {
            r.anchor(Base64VecU8(vec![1; 31]));
        })
        .contains("32 bytes"));
        ctx("a.test", 4 * DAY);
        assert!(refused(|| {
            r.anchor(Base64VecU8(vec![1; 32]));
        })
        .contains("only the aggregator"));
    }

    /// One key used to flood the registry with anchors in a single block.
    #[test]
    fn anchors_have_a_minimum_interval() {
        let mut r = registry();
        ctx("agg.test", 2 * DAY);
        r.anchor(Base64VecU8(vec![1; 32]));
        assert!(refused(|| {
            r.anchor(Base64VecU8(vec![2; 32]));
        })
        .contains("too recently"));
        ctx("agg.test", 2 * DAY + MIN_ANCHOR_INTERVAL_NS - 1);
        assert!(refused(|| {
            r.anchor(Base64VecU8(vec![2; 32]));
        })
        .contains("too recently"));
        ctx("agg.test", 2 * DAY + MIN_ANCHOR_INTERVAL_NS);
        assert_eq!(r.anchor(Base64VecU8(vec![2; 32])), U64(1));
    }

    /// The caller pays the storage it adds; nothing attached, nothing written.
    #[test]
    fn storage_is_paid_by_the_caller() {
        let mut r = registry();
        ctx_with("agg.test", 2 * DAY, NearToken::from_yoctonear(0));
        assert!(refused(|| {
            r.anchor(Base64VecU8(vec![1; 32]));
        })
        .contains("for storage"));
        ctx_with("a.test", 2 * DAY, NearToken::from_yoctonear(0));
        assert!(refused(|| {
            r.propose(publish("k", 1, 10 * DAY));
        })
        .contains("for storage"));
    }

    /// The storage an anchor adds is charged at the network's price per byte, and the excess refunded.
    #[test]
    fn storage_cost_is_charged_and_the_excess_refunded() {
        let mut r = registry();
        ctx("agg.test", 2 * DAY);
        let before = env::storage_usage();
        r.anchor(Base64VecU8(vec![1; 32]));
        let cost = env::storage_byte_cost().as_yoctonear() * u128::from(env::storage_usage() - before);
        assert!(cost > 0);
        assert_eq!(refunds_to("agg.test"), DEPOSIT.as_yoctonear() - cost, "the excess goes back to the caller");

        // Each anchor adds the same number of bytes. Exactly the cost: accepted, nothing refunded.
        ctx_with("agg.test", 3 * DAY, NearToken::from_yoctonear(cost));
        r.anchor(Base64VecU8(vec![2; 32]));
        assert_eq!(refunds_to("agg.test"), 0);
        // One yoctoNEAR less: refused.
        ctx_with("agg.test", 4 * DAY, NearToken::from_yoctonear(cost - 1));
        assert!(refused(|| {
            r.anchor(Base64VecU8(vec![3; 32]));
        })
        .contains("for storage"));
    }

    /// Total of the transfers this call created towards `who`.
    fn refunds_to(who: &str) -> u128 {
        near_sdk::test_utils::get_created_receipts()
            .into_iter()
            .filter(|receipt| receipt.receiver_id == acc(who))
            .flat_map(|receipt| receipt.actions)
            .filter_map(|action| match action {
                near_sdk::mock::MockAction::Transfer { deposit, .. } => Some(deposit.as_yoctonear()),
                _ => None,
            })
            .sum()
    }

    /// One owner cannot fill the contract with proposals.
    #[test]
    fn pending_proposals_are_limited_per_owner() {
        let mut r = registry();
        ctx("a.test", DAY);
        let ids: Vec<U64> = (0..MAX_PENDING_PER_OWNER).map(|i| r.propose(publish("k", i as u8, 9 * DAY))).collect();
        assert!(refused(|| {
            r.propose(publish("k", 99, 9 * DAY));
        })
        .contains("too many pending"));
        ctx("b.test", DAY);
        r.propose(publish("k", 98, 9 * DAY));
        ctx("a.test", DAY);
        r.cancel(ids[0]);
        r.propose(publish("k", 97, 9 * DAY));
    }

    #[test]
    fn publishing_needs_both_owners() {
        let mut r = registry();
        let action = publish("measure", 1, 9 * DAY);
        ctx("a.test", DAY);
        let id = r.propose(action.clone());
        assert!(refused(|| r.confirm(id, action.clone())).contains("the other owner"), "the proposer alone");

        ctx("eve.test", DAY);
        assert!(refused(|| r.confirm(id, action.clone())).contains("only an owner"));
        assert!(refused(|| {
            r.propose(publish("measure", 2, 9 * DAY));
        })
        .contains("only an owner"));

        assert!(r.history("measure".into()).is_empty(), "nothing applied yet");
        ctx("b.test", DAY);
        r.confirm(id, action.clone());
        assert_eq!(r.history("measure".into()).len(), 1);
        assert!(refused(|| r.confirm(id, action)).contains("unknown proposal"), "confirmed once only");
    }

    /// The confirmer restates the action, can read it first, and an old proposal expires.
    #[test]
    fn a_confirmation_names_the_action_and_old_proposals_expire() {
        let mut r = registry();
        let action = RegistryAction::SetAggregator { aggregator: acc("new.test") };
        ctx("a.test", DAY);
        let id = r.propose(action.clone());
        assert_eq!(r.get_proposal(id).unwrap().action, action);
        ctx("b.test", 9 * DAY);
        let other = RegistryAction::SetAggregator { aggregator: acc("other.test") };
        assert!(refused(|| r.confirm(id, other)).contains("differs"));
        ctx("b.test", DAY + PROPOSAL_TTL_NS);
        assert!(refused(|| r.confirm(id, action.clone())).contains("expired"));
        ctx("b.test", DAY + PROPOSAL_TTL_NS - 1);
        r.confirm(id, action);
        assert_eq!(r.aggregator(), acc("new.test"));
    }

    #[test]
    fn publish_delay_is_enforced_when_confirmed() {
        let mut r = registry();
        let action = publish("measure", 1, 8 * DAY);
        ctx("a.test", DAY);
        let id = r.propose(action.clone());
        ctx("b.test", 2 * DAY);
        assert!(refused(|| r.confirm(id, action)).contains("too soon"), "stale proposal cannot shorten the delay");

        enact(&mut r, publish("measure", 1, 8 * DAY), DAY);
        ctx("b.test", 7 * DAY);
        assert_eq!(r.active("measure".into()), None, "not in force before valid_from");
        ctx("b.test", 8 * DAY);
        assert_eq!(r.active("measure".into()), Some(val(1)));
    }

    /// A date far in the future would block the topic for ever.
    #[test]
    fn a_value_cannot_be_scheduled_too_far_ahead() {
        let mut r = registry();
        let action = publish("k", 1, u64::MAX);
        ctx("a.test", DAY);
        let id = r.propose(action.clone());
        ctx("b.test", DAY);
        assert!(refused(|| r.confirm(id, action)).contains("too far ahead"));
        enact(&mut r, publish("k", 1, DAY + MAX_PUBLISH_AHEAD_NS), DAY);
    }

    #[test]
    fn values_are_append_only_with_increasing_dates() {
        let mut r = registry();
        enact(&mut r, publish("k", 1, 8 * DAY), DAY);
        let dup = publish("k", 1, 20 * DAY);
        ctx("a.test", 9 * DAY);
        let id = r.propose(dup.clone());
        ctx("b.test", 9 * DAY);
        assert!(refused(|| r.confirm(id, dup)).contains("already published"));

        enact(&mut r, publish("k", 2, 20 * DAY), 9 * DAY);
        ctx("b.test", 19 * DAY);
        assert_eq!(r.active("k".into()), Some(val(1)));
        ctx("b.test", 20 * DAY);
        assert_eq!(r.active("k".into()), Some(val(2)));
    }

    /// A sleeper value: a value stacked behind another one is refused, and revoking the value in force
    /// never brings an older one back.
    #[test]
    fn no_value_can_wait_hidden_behind_another() {
        let mut r = registry();
        enact(&mut r, publish("measure", 1, 8 * DAY), DAY);
        let stacked = publish("measure", 66, 9 * DAY);
        ctx("a.test", DAY);
        let id = r.propose(stacked.clone());
        ctx("b.test", DAY);
        assert!(refused(|| r.confirm(id, stacked)).contains("still pending"));

        // 66 in force, then a good value 2, then 2 is revoked.
        enact(&mut r, publish("measure", 66, 16 * DAY), 8 * DAY);
        enact(&mut r, publish("measure", 2, 25 * DAY), 17 * DAY);
        ctx("x.test", 100 * DAY);
        assert_eq!(r.active("measure".into()), Some(val(2)));
        ctx("a.test", 100 * DAY);
        r.emergency(revoke("measure", 2));
        ctx("x.test", 100 * DAY);
        assert_eq!(r.active("measure".into()), None, "no older value comes back");
    }

    #[test]
    fn a_value_cancelled_before_its_date_is_skipped() {
        let mut r = registry();
        enact(&mut r, publish("k", 1, 8 * DAY), DAY);
        enact(&mut r, publish("k", 2, 20 * DAY), 9 * DAY);
        ctx("a.test", 10 * DAY);
        r.emergency(revoke("k", 2));
        ctx("x.test", 21 * DAY);
        assert_eq!(r.active("k".into()), Some(val(1)), "2 never took effect");
        assert_eq!(r.history("k".into())[1].revoked_at, Some(U64(10 * DAY)), "the history keeps it");

        ctx("a.test", 14 * DAY);
        r.emergency(revoke("k", 1));
        ctx("x.test", 14 * DAY);
        assert_eq!(r.active("k".into()), None);
        let back = publish("k", 1, 30 * DAY);
        ctx("a.test", 14 * DAY);
        let id = r.propose(back.clone());
        ctx("b.test", 14 * DAY);
        assert!(refused(|| r.confirm(id, back)).contains("cannot come back"));
        enact(&mut r, publish("k", 3, 30 * DAY), 14 * DAY);
    }

    /// One owner alone can react to an emergency, and nothing more.
    #[test]
    fn one_owner_can_revoke_or_raise_the_incident_level_alone() {
        let mut r = registry();
        enact(&mut r, publish("k", 1, 8 * DAY), DAY);
        ctx("b.test", 9 * DAY);
        r.emergency(RegistryAction::SetIncident { level: 2 });
        assert_eq!(r.incident_level(), 2);
        assert!(refused(|| r.emergency(RegistryAction::SetIncident { level: 1 })).contains("only raise"));
        assert!(refused(|| r.emergency(publish("k", 2, 20 * DAY))).contains("both owners"));
        assert!(refused(|| r.emergency(RegistryAction::SetAggregator { aggregator: acc("x.test") }))
            .contains("both owners"));
        r.emergency(revoke("k", 1));
        assert_eq!(r.active("k".into()), None);
        ctx("eve.test", 9 * DAY);
        assert!(refused(|| r.emergency(RegistryAction::SetIncident { level: 3 })).contains("only an owner"));
    }

    /// Lowering the incident level, changing the aggregator or an owner gives notice first.
    #[test]
    fn lowering_the_incident_level_waits_for_the_notice_period() {
        let mut r = registry();
        ctx("a.test", DAY);
        r.emergency(RegistryAction::SetIncident { level: 3 });
        let lower = RegistryAction::SetIncident { level: 0 };
        let id = r.propose(lower.clone());
        ctx("b.test", DAY + ADMIN_DELAY_NS - 1);
        assert!(refused(|| r.confirm(id, lower.clone())).contains("notice period"));
        ctx("b.test", DAY + ADMIN_DELAY_NS);
        r.confirm(id, lower);
        assert_eq!(r.incident_level(), 0);

        enact(&mut r, RegistryAction::SetIncident { level: 1 }, 20 * DAY);
        assert_eq!(r.incident_level(), 1, "raising needs no notice");
        ctx("a.test", 20 * DAY);
        assert!(refused(|| {
            r.propose(RegistryAction::SetIncident { level: 9 });
        })
        .contains("bad incident level"));
    }

    /// An owner can be replaced, with both owners and notice.
    #[test]
    fn an_owner_can_be_replaced() {
        let mut r = registry();
        let change = RegistryAction::ChangeOwner { old: acc("a.test"), new: acc("c.test") };
        ctx("b.test", DAY);
        let id = r.propose(change.clone());
        ctx("a.test", DAY);
        assert!(refused(|| r.confirm(id, change.clone())).contains("notice period"));
        ctx("a.test", DAY + ADMIN_DELAY_NS);
        r.confirm(id, change);
        assert_eq!(r.owners(), [acc("c.test"), acc("b.test")]);
        ctx("a.test", 9 * DAY);
        assert!(refused(|| r.emergency(RegistryAction::SetIncident { level: 1 })).contains("only an owner"));
        ctx("c.test", 9 * DAY);
        r.emergency(RegistryAction::SetIncident { level: 1 });

        ctx("c.test", 9 * DAY);
        for bad in [
            RegistryAction::ChangeOwner { old: acc("x.test"), new: acc("d.test") },
            RegistryAction::ChangeOwner { old: acc("c.test"), new: acc("b.test") },
            RegistryAction::ChangeOwner { old: acc("c.test"), new: acc("agg.test") },
            RegistryAction::SetAggregator { aggregator: acc("b.test") },
        ] {
            assert!(!refused(|| {
                r.propose(bad.clone());
            })
            .is_empty());
        }
    }

    #[test]
    fn cancel_and_input_limits() {
        let mut r = registry();
        let action = publish("k", 1, 9 * DAY);
        ctx("a.test", DAY);
        let id = r.propose(action.clone());
        ctx("b.test", DAY);
        assert!(refused(|| r.cancel(id)).contains("only the proposer"));
        ctx("a.test", DAY);
        r.cancel(id);
        ctx("b.test", DAY);
        assert!(refused(|| r.confirm(id, action)).contains("unknown proposal"));

        for topic in ["x".repeat(MAX_TOPIC_LEN + 1), "Measure".into(), "a b".into(), "".into()] {
            assert!(refused(|| {
                r.propose(RegistryAction::Publish { topic, value: val(1), valid_from: U64(9 * DAY) });
            })
            .contains("bad topic"));
        }
        assert!(refused(|| {
            r.propose(RegistryAction::Publish {
                topic: "k".into(),
                value: Base64VecU8(vec![1; MAX_VALUE_LEN + 1]),
                valid_from: U64(9 * DAY),
            });
        })
        .contains("bad value"));
    }

    #[test]
    fn aggregator_change_takes_two_owners_and_notice() {
        let mut r = registry();
        enact_at(&mut r, RegistryAction::SetAggregator { aggregator: acc("new.test") }, DAY, DAY + ADMIN_DELAY_NS);
        assert_eq!(r.aggregator(), acc("new.test"));
        ctx("new.test", 9 * DAY);
        r.anchor(Base64VecU8(vec![1; 32]));
    }

    /// Two proposals valid alone but not together: the second is checked again against the new state.
    #[test]
    fn a_confirmation_checks_the_action_again() {
        let mut r = registry();
        let set = RegistryAction::SetAggregator { aggregator: acc("x.test") };
        let change = RegistryAction::ChangeOwner { old: acc("b.test"), new: acc("x.test") };
        ctx("a.test", DAY);
        let first = r.propose(set.clone());
        ctx("b.test", DAY);
        let second = r.propose(change.clone());
        ctx("b.test", DAY + ADMIN_DELAY_NS);
        r.confirm(first, set);
        ctx("a.test", DAY + ADMIN_DELAY_NS);
        assert!(refused(|| r.confirm(second, change)).contains("cannot be an owner"));

        let mut r = registry();
        let one = RegistryAction::ChangeOwner { old: acc("a.test"), new: acc("c.test") };
        let two = RegistryAction::ChangeOwner { old: acc("a.test"), new: acc("d.test") };
        ctx("b.test", DAY);
        let first = r.propose(one.clone());
        let second = r.propose(two.clone());
        ctx("a.test", DAY + ADMIN_DELAY_NS);
        r.confirm(first, one);
        ctx("c.test", DAY + ADMIN_DELAY_NS);
        assert!(refused(|| r.confirm(second, two)).contains("not an owner"), "a.test is gone already");
    }

    /// A replaced owner's pending proposals are removed, and its slot starts empty.
    #[test]
    fn a_replaced_owner_leaves_no_proposal_behind() {
        let mut r = registry();
        let stale = RegistryAction::SetAggregator { aggregator: acc("old-agg.test") };
        ctx("a.test", DAY);
        let old = r.propose(stale.clone());
        let change = RegistryAction::ChangeOwner { old: acc("a.test"), new: acc("c.test") };
        ctx("b.test", DAY);
        let id = r.propose(change.clone());
        ctx("a.test", DAY + ADMIN_DELAY_NS);
        r.confirm(id, change);
        assert!(r.get_proposal(old).is_none());
        ctx("b.test", DAY + ADMIN_DELAY_NS);
        assert!(refused(|| r.confirm(old, stale)).contains("unknown proposal"));
        ctx("c.test", DAY + ADMIN_DELAY_NS);
        for i in 0..MAX_PENDING_PER_OWNER {
            r.propose(publish("k", i as u8, 30 * DAY));
        }
    }

    /// A value revoked by one owner alone can be restored by both, with notice.
    #[test]
    fn an_emergency_revocation_can_be_undone_by_both_owners() {
        let mut r = registry();
        enact(&mut r, publish("k", 1, 8 * DAY), DAY);
        ctx("b.test", 9 * DAY);
        r.emergency(revoke("k", 1));
        ctx("x.test", 9 * DAY);
        assert_eq!(r.active("k".into()), None);
        assert!(r.history("k".into())[0].emergency);
        let restore = RegistryAction::Restore { topic: "k".into(), value: val(1) };
        enact_at(&mut r, restore.clone(), 9 * DAY, 9 * DAY + ADMIN_DELAY_NS);
        ctx("x.test", 17 * DAY);
        assert_eq!(r.active("k".into()), Some(val(1)));

        // A revocation by both owners is final.
        enact(&mut r, revoke("k", 1), 20 * DAY);
        ctx("a.test", 20 * DAY);
        let id = r.propose(restore.clone());
        ctx("b.test", 20 * DAY + ADMIN_DELAY_NS);
        assert!(refused(|| r.confirm(id, restore)).contains("no value revoked by one owner"));
    }

    /// Both owners can make an emergency revocation final, so it can no longer be restored.
    #[test]
    fn an_emergency_revocation_can_be_made_final() {
        let mut r = registry();
        enact(&mut r, publish("k", 1, 8 * DAY), DAY);
        ctx("b.test", 9 * DAY);
        r.emergency(revoke("k", 1));
        let revoked_at = r.history("k".into())[0].revoked_at;
        enact(&mut r, revoke("k", 1), 10 * DAY);
        let entry = &r.history("k".into())[0];
        assert!(!entry.emergency, "now final");
        assert_eq!(entry.revoked_at, revoked_at, "the revocation date is kept");
        let restore = RegistryAction::Restore { topic: "k".into(), value: val(1) };
        ctx("a.test", 10 * DAY);
        let id = r.propose(restore.clone());
        ctx("b.test", 10 * DAY + ADMIN_DELAY_NS);
        assert!(refused(|| r.confirm(id, restore)).contains("no value revoked by one owner"));
        // Revoking again what both owners already revoked is refused.
        let again = revoke("k", 1);
        ctx("a.test", 20 * DAY);
        let id = r.propose(again.clone());
        ctx("b.test", 20 * DAY);
        assert!(refused(|| r.confirm(id, again)).contains("unknown value"));
    }

    /// Expired proposals no longer count against the limit.
    #[test]
    fn expired_proposals_free_their_place() {
        let mut r = registry();
        ctx("a.test", DAY);
        let ids: Vec<U64> = (0..MAX_PENDING_PER_OWNER).map(|i| r.propose(publish("k", i as u8, 9 * DAY))).collect();
        assert!(refused(|| {
            r.propose(publish("k", 99, 9 * DAY));
        })
        .contains("too many pending"));
        ctx("a.test", DAY + PROPOSAL_TTL_NS);
        r.propose(publish("k", 98, 40 * DAY));
        for id in ids {
            assert!(r.get_proposal(id).is_none(), "an expired proposal is removed");
        }
    }

    /// One owner replaces a lost owner after a long delay, unless that owner vetoes.
    #[test]
    fn a_lost_owner_can_be_replaced_by_the_other_unless_it_vetoes() {
        let mut r = registry();
        ctx("a.test", DAY);
        let id = r.propose_takeover(acc("c.test"));
        let action = RegistryAction::ChangeOwner { old: acc("b.test"), new: acc("c.test") };
        ctx("a.test", DAY + TAKEOVER_DELAY_NS - 1);
        assert!(refused(|| r.confirm(id, action.clone())).contains("delay is not over"));
        ctx("b.test", DAY + TAKEOVER_DELAY_NS);
        assert!(refused(|| r.confirm(id, action.clone())).contains("confirmed by its proposer"));
        ctx("a.test", DAY + TAKEOVER_DELAY_NS);
        r.confirm(id, action);
        assert_eq!(r.owners(), [acc("a.test"), acc("c.test")]);

        let mut r = registry();
        ctx("a.test", DAY);
        let id = r.propose_takeover(acc("c.test"));
        assert!(refused(|| r.veto(id)).contains("only the owner being replaced"));
        ctx("b.test", 2 * DAY);
        r.veto(id);
        ctx("a.test", DAY + TAKEOVER_DELAY_NS);
        let action = RegistryAction::ChangeOwner { old: acc("b.test"), new: acc("c.test") };
        assert!(refused(|| r.confirm(id, action)).contains("unknown proposal"));
        ctx("b.test", 2 * DAY);
        let normal = r.propose(RegistryAction::SetIncident { level: 1 });
        ctx("a.test", 2 * DAY);
        assert!(refused(|| r.veto(normal)).contains("only the owner being replaced"), "veto is for takeovers");
    }
}
