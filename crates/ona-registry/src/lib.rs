//! `ona-registry`: public anchors and published parameters. Holds no funds. Draft, not audited.
//!
//! Every change of a published value needs both owners: one proposes, the other confirms. New
//! values only take effect after a delay, so users can see a change coming and leave. Revocation
//! and the incident level are immediate, because they only ever reduce trust.

use near_sdk::collections::{LookupMap, Vector};
use near_sdk::json_types::{Base64VecU8, U64};
use near_sdk::{env, near, require, AccountId, PanicOnDefault};

pub const MIN_PUBLISH_DELAY_NS: u64 = 7 * 24 * 3_600_000_000_000;
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
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Anchor {
    pub seq: U64,
    pub root: Base64VecU8,
    pub count: u32,
    pub timestamp: U64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub value: Base64VecU8,
    pub valid_from: U64,
    pub revoked: bool,
}

#[near(serializers = [borsh])]
struct Proposal {
    action: RegistryAction,
    proposer: AccountId,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Registry {
    owners: [AccountId; 2],
    aggregator: AccountId,
    incident_level: u8,
    next_proposal: u64,
    proposals: LookupMap<u64, Proposal>,
    anchors: Vector<Anchor>,
    entries: LookupMap<String, Vec<Entry>>,
}

#[near]
impl Registry {
    #[init]
    pub fn new(owners: [AccountId; 2], aggregator: AccountId) -> Self {
        require!(owners[0] != owners[1], "the two owners must differ");
        Self {
            owners,
            aggregator,
            incident_level: 0,
            next_proposal: 0,
            proposals: LookupMap::new(b"p".to_vec()),
            anchors: Vector::new(b"a".to_vec()),
            entries: LookupMap::new(b"e".to_vec()),
        }
    }

    pub fn anchor(&mut self, root: Base64VecU8, count: u32) -> U64 {
        require!(env::predecessor_account_id() == self.aggregator, "only the aggregator can anchor");
        require!(root.0.len() == 32, "root must be 32 bytes");
        let seq = U64(self.anchors.len());
        self.anchors.push(&Anchor { seq, root, count, timestamp: U64(env::block_timestamp()) });
        seq
    }

    pub fn propose(&mut self, action: RegistryAction) -> U64 {
        let proposer = self.require_owner();
        Self::validate(&action);
        let id = self.next_proposal;
        self.next_proposal += 1;
        self.proposals.insert(&id, &Proposal { action, proposer });
        U64(id)
    }

    /// Applies a proposal. Only the owner who did not propose it can confirm.
    pub fn confirm(&mut self, id: U64) {
        let confirmer = self.require_owner();
        let proposal =
            self.proposals.get(&id.0).unwrap_or_else(|| env::panic_str("unknown proposal"));
        require!(confirmer != proposal.proposer, "the other owner must confirm");
        self.proposals.remove(&id.0);
        self.apply(proposal.action);
    }

    pub fn cancel(&mut self, id: U64) {
        self.require_owner();
        require!(self.proposals.remove(&id.0).is_some(), "unknown proposal");
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

    /// The most recent value in force now: already valid and not revoked.
    pub fn active(&self, topic: String) -> Option<Base64VecU8> {
        let now = env::block_timestamp();
        self.entries
            .get(&topic)?
            .into_iter()
            .rev()
            .find(|e| !e.revoked && e.valid_from.0 <= now)
            .map(|e| e.value)
    }

    /// Everything ever published on a topic, so a wallet can see scheduled changes.
    pub fn history(&self, topic: String) -> Vec<Entry> {
        self.entries.get(&topic).unwrap_or_default()
    }
}

impl Registry {
    fn require_owner(&self) -> AccountId {
        let caller = env::predecessor_account_id();
        require!(self.owners.contains(&caller), "only an owner can do this");
        caller
    }

    fn validate(action: &RegistryAction) {
        let check_topic = |t: &str| require!(!t.is_empty() && t.len() <= MAX_TOPIC_LEN, "bad topic");
        match action {
            RegistryAction::Publish { topic, value, .. } | RegistryAction::Revoke { topic, value } => {
                check_topic(topic);
                require!(!value.0.is_empty() && value.0.len() <= MAX_VALUE_LEN, "bad value");
            }
            RegistryAction::SetIncident { level } => {
                require!(*level <= MAX_INCIDENT_LEVEL, "bad incident level");
            }
            RegistryAction::SetAggregator { .. } => {}
        }
    }

    fn apply(&mut self, action: RegistryAction) {
        match action {
            RegistryAction::Publish { topic, value, valid_from } => {
                // Checked at confirmation: an old proposal must not shorten the notice period.
                require!(
                    valid_from.0 >= env::block_timestamp() + MIN_PUBLISH_DELAY_NS,
                    "valid_from is too soon"
                );
                let mut list = self.entries.get(&topic).unwrap_or_default();
                require!(!list.iter().any(|e| e.value == value), "value already published");
                if let Some(last) = list.last() {
                    require!(valid_from.0 > last.valid_from.0, "valid_from must increase");
                }
                list.push(Entry { value, valid_from, revoked: false });
                self.entries.insert(&topic, &list);
            }
            RegistryAction::Revoke { topic, value } => {
                let mut list = self.entries.get(&topic).unwrap_or_default();
                let entry = list
                    .iter_mut()
                    .find(|e| e.value == value)
                    .unwrap_or_else(|| env::panic_str("unknown value"));
                entry.revoked = true;
                self.entries.insert(&topic, &list);
            }
            RegistryAction::SetIncident { level } => self.incident_level = level,
            RegistryAction::SetAggregator { aggregator } => self.aggregator = aggregator,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const DAY: u64 = 24 * 3_600_000_000_000;

    fn acc(s: &str) -> AccountId {
        s.parse().unwrap()
    }

    fn ctx(who: &str, now: u64) {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(acc(who))
            .block_timestamp(now)
            .storage_usage(10_000)
            .build());
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

    fn enact(r: &mut Registry, action: RegistryAction, now: u64) {
        ctx("a.test", now);
        let id = r.propose(action);
        ctx("b.test", now);
        r.confirm(id);
    }

    #[test]
    fn owners_must_differ() {
        ctx("deployer.test", DAY);
        assert!(refused(|| {
            Registry::new([acc("a.test"), acc("a.test")], acc("agg.test"));
        })
        .contains("must differ"));
    }

    #[test]
    fn anchors_are_append_only_and_restricted() {
        let mut r = registry();
        ctx("agg.test", 2 * DAY);
        assert_eq!(r.anchor(Base64VecU8(vec![1; 32]), 5), U64(0));
        ctx("agg.test", 3 * DAY);
        assert_eq!(r.anchor(Base64VecU8(vec![2; 32]), 9), U64(1));
        assert_eq!(r.get_anchor(U64(0)).unwrap().count, 5);
        let latest = r.latest_anchor().unwrap();
        assert_eq!((latest.seq, latest.count, latest.timestamp), (U64(1), 9, U64(3 * DAY)));

        assert!(refused(|| {
            r.anchor(Base64VecU8(vec![1; 31]), 1);
        })
        .contains("32 bytes"));
        ctx("a.test", 3 * DAY);
        assert!(refused(|| {
            r.anchor(Base64VecU8(vec![1; 32]), 1);
        })
        .contains("only the aggregator"));
    }

    #[test]
    fn publishing_needs_both_owners() {
        let mut r = registry();
        ctx("a.test", DAY);
        let id = r.propose(publish("measure", 1, 9 * DAY));
        assert!(refused(|| r.confirm(id)).contains("the other owner"), "the proposer alone");

        ctx("eve.test", DAY);
        assert!(refused(|| r.confirm(id)).contains("only an owner"));
        assert!(refused(|| {
            r.propose(publish("measure", 2, 9 * DAY));
        })
        .contains("only an owner"));

        assert!(r.history("measure".into()).is_empty(), "nothing applied yet");
        ctx("b.test", DAY);
        r.confirm(id);
        assert_eq!(r.history("measure".into()).len(), 1);
        assert!(refused(|| r.confirm(id)).contains("unknown proposal"), "confirmed once only");
    }

    #[test]
    fn publish_delay_is_enforced_when_confirmed() {
        let mut r = registry();
        ctx("a.test", DAY);
        let id = r.propose(publish("measure", 1, 8 * DAY));
        ctx("b.test", 2 * DAY);
        assert!(refused(|| r.confirm(id)).contains("too soon"), "stale proposal cannot shorten the delay");

        enact(&mut r, publish("measure", 1, 8 * DAY), DAY);
        ctx("b.test", 7 * DAY);
        assert_eq!(r.active("measure".into()), None, "not in force before valid_from");
        ctx("b.test", 8 * DAY);
        assert_eq!(r.active("measure".into()), Some(val(1)));
    }

    #[test]
    fn values_are_append_only_with_increasing_dates() {
        let mut r = registry();
        enact(&mut r, publish("k", 1, 8 * DAY), DAY);
        ctx("a.test", DAY);
        let dup = r.propose(publish("k", 1, 20 * DAY));
        ctx("b.test", DAY);
        assert!(refused(|| r.confirm(dup)).contains("already published"));

        ctx("a.test", DAY);
        let early = r.propose(publish("k", 2, 8 * DAY));
        ctx("b.test", DAY);
        assert!(refused(|| r.confirm(early)).contains("must increase"));

        enact(&mut r, publish("k", 2, 12 * DAY), DAY);
        ctx("b.test", 9 * DAY);
        assert_eq!(r.active("k".into()), Some(val(1)));
        ctx("b.test", 12 * DAY);
        assert_eq!(r.active("k".into()), Some(val(2)));
    }

    #[test]
    fn revocation_falls_back_and_is_immediate() {
        let mut r = registry();
        enact(&mut r, publish("k", 1, 8 * DAY), DAY);
        enact(&mut r, publish("k", 2, 12 * DAY), DAY);
        enact(&mut r, RegistryAction::Revoke { topic: "k".into(), value: val(2) }, 13 * DAY);
        ctx("b.test", 13 * DAY);
        assert_eq!(r.active("k".into()), Some(val(1)));
        assert!(r.history("k".into())[1].revoked, "the history keeps the revoked value");

        enact(&mut r, RegistryAction::Revoke { topic: "k".into(), value: val(1) }, 14 * DAY);
        ctx("b.test", 14 * DAY);
        assert_eq!(r.active("k".into()), None);
    }

    #[test]
    fn incident_level_needs_both_owners_and_a_valid_level() {
        let mut r = registry();
        enact(&mut r, RegistryAction::SetIncident { level: 2 }, DAY);
        assert_eq!(r.incident_level(), 2);
        ctx("a.test", DAY);
        assert!(refused(|| {
            r.propose(RegistryAction::SetIncident { level: 9 });
        })
        .contains("bad incident level"));
    }

    #[test]
    fn cancel_and_input_limits() {
        let mut r = registry();
        ctx("a.test", DAY);
        let id = r.propose(publish("k", 1, 9 * DAY));
        ctx("b.test", DAY);
        r.cancel(id);
        assert!(refused(|| r.confirm(id)).contains("unknown proposal"));

        let long = "x".repeat(MAX_TOPIC_LEN + 1);
        assert!(refused(|| {
            r.propose(RegistryAction::Publish { topic: long, value: val(1), valid_from: U64(9 * DAY) });
        })
        .contains("bad topic"));
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
    fn aggregator_change_takes_two_owners() {
        let mut r = registry();
        enact(&mut r, RegistryAction::SetAggregator { aggregator: acc("new.test") }, DAY);
        assert_eq!(r.aggregator(), acc("new.test"));
        ctx("new.test", DAY);
        r.anchor(Base64VecU8(vec![1; 32]), 1);
    }
}
