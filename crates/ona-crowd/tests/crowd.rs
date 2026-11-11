use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;

use ed25519_dalek::SigningKey;
use ona_crowd::chain::{check_event, check_exit_caps, execute, MemoryChain};
use ona_crowd::near::{check_chain_id, check_settings, NearChain, NearSettings};
use ona_crowd::parades::{agent_transactions, compare, scenarios, table};
use ona_crowd::{
    candidates, guesses, implicit_account, posterior, posterior_from, privacy, simulate, simulate_secret, write_keys,
    yield_guess, AgentRules, Config, EventKind, PublicEvent, Simulation, TrueRoute, Vault, VaultKind,
};

fn config(seed: u64) -> Config {
    Config {
        seed,
        users: 60,
        vaults: vec![
            Vault { kind: VaultKind::Staking, contract: "staking.example.testnet".into() },
            Vault { kind: VaultKind::Lending, contract: "lending.example.testnet".into() },
        ],
        ..Config::default()
    }
}

fn run(seed: u64) -> (Config, Simulation) {
    let c = config(seed);
    let sim = simulate(&c).unwrap();
    (c, sim)
}

fn event(sim: &Simulation, id: usize) -> &PublicEvent {
    let e = &sim.timeline[id];
    assert_eq!(e.id, id);
    e
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("ona-crowd-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn the_same_seed_gives_the_same_crowd() {
    let (_, a) = run(7);
    let (_, b) = run(7);
    assert_eq!(a.timeline, b.timeline);
    assert_eq!(serde_json::to_string(&a.truth).unwrap(), serde_json::to_string(&b.truth).unwrap());
    let keys = |s: &Simulation| s.users.iter().map(|u| u.key.to_bytes()).collect::<Vec<_>>();
    assert_eq!(keys(&a), keys(&b));

    let (_, c) = run(8);
    assert_ne!(a.timeline, c.timeline);
    assert_ne!(keys(&a), keys(&c));
}

#[test]
fn a_secret_seed_ignores_the_configured_one() {
    let c = config(7);
    let fixed = simulate(&c).unwrap();
    let a = simulate_secret(&c, [1u8; 32]).unwrap();
    let again = simulate_secret(&c, [1u8; 32]).unwrap();
    let other = simulate_secret(&c, [2u8; 32]).unwrap();
    let first_key = |s: &Simulation| s.users[0].key.to_bytes();
    assert_eq!(first_key(&a), first_key(&again));
    assert_ne!(first_key(&a), first_key(&other));
    assert_ne!(first_key(&a), first_key(&fixed));
    let mut changed = c.clone();
    changed.seed = 8;
    assert_eq!(first_key(&simulate_secret(&changed, [1u8; 32]).unwrap()), first_key(&a));
}

#[test]
fn every_user_has_its_own_implicit_account() {
    let (_, sim) = run(1);
    let mut seen = BTreeSet::new();
    for u in &sim.users {
        let account = u.account();
        assert_eq!(account.len(), 64);
        assert!(account.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(account, implicit_account(&u.key));
        assert!(seen.insert(account));
    }
}

#[test]
fn the_simulation_exercises_every_path() {
    let (c, sim) = run(1);
    let r = &sim.truth.requests;
    assert!(r.iter().any(|r| r.profile.is_partial() && r.withdrawn_at.is_some()));
    assert!(r.iter().any(|r| !r.profile.is_partial() && r.withdrawn_at.is_some()));
    for (v, vault) in c.vaults.iter().enumerate() {
        assert!(r.iter().any(|r| r.profile.vault == v && r.vault == vault.contract && r.withdrawn_at.is_some()));
    }
    let used: BTreeSet<u64> = sim.timeline.iter().map(|e| e.denomination).collect();
    assert_eq!(used, c.denominations.iter().copied().collect());
}

#[test]
fn placements_wait_for_k_requests_and_the_minimum_wait() {
    let (c, sim) = run(2);
    let rules = &c.agent;
    let mut batches: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, r) in sim.truth.requests.iter().enumerate() {
        let Some(placed) = r.placed_at else {
            assert!(r.placement_events.is_empty());
            continue;
        };
        assert!(placed >= r.profile.request_at + rules.min_wait_secs);
        assert!(!r.placement_events.is_empty());
        for &id in &r.placement_events {
            let e = event(&sim, id);
            assert_eq!(e.kind, EventKind::Placement);
            assert_eq!(e.at_secs, placed);
            assert_eq!((e.from.as_str(), e.to.as_str()), (rules.account.as_str(), r.vault.as_str()));
            batches.entry(id).or_default().push(i);
        }
    }
    assert!(!batches.is_empty());
    for (id, members) in &batches {
        assert!(members.len() >= rules.k, "placement {id} mixes only {} requests", members.len());
        // The batch carries exactly the notes of its requests in that denomination.
        let e = event(&sim, *id);
        let notes: u32 = members
            .iter()
            .flat_map(|&i| &sim.truth.requests[i].profile.notes)
            .filter(|n| n.denomination == e.denomination)
            .map(|n| n.count)
            .sum();
        assert_eq!(notes, e.count);
    }
}

#[test]
fn a_batch_runs_within_the_window_after_it_is_allowed() {
    let (c, sim) = run(3);
    let rules = &c.agent;
    let mut delays = BTreeSet::new();
    for vault in &c.vaults {
        let mut times: Vec<u64> =
            sim.truth.requests.iter().filter(|r| r.vault == vault.contract).filter_map(|r| r.placed_at).collect();
        times.sort_unstable();
        times.dedup();
        let mut previous: Option<u64> = None;
        for &t in &times {
            let mut ready: Vec<u64> = sim
                .truth
                .requests
                .iter()
                .filter(|r| r.vault == vault.contract && r.placed_at == Some(t))
                .map(|r| r.profile.request_at + rules.min_wait_secs)
                .collect();
            ready.sort_unstable();
            let allowed = ready[rules.k - 1].max(previous.map_or(0, |p| p + 1));
            assert!(allowed <= t && t < allowed + rules.window_secs, "batch at {t} allowed at {allowed}");
            delays.insert(t - allowed);
            previous = Some(t);
        }
    }
    assert!(delays.len() > 1, "batch moments must vary");
}

#[test]
fn exits_respect_the_minimum_stay_and_go_back_to_the_deposit_account() {
    let (c, sim) = run(4);
    let rules = &c.agent;
    let mut withdrawal_members: BTreeMap<usize, usize> = BTreeMap::new();
    let mut payments = 0;
    for r in &sim.truth.requests {
        let Some(out) = r.withdrawn_at else {
            assert!(r.payment_events.is_empty() && r.withdrawal_events.is_empty());
            continue;
        };
        let placed = r.placed_at.expect("withdrawn without being placed");
        assert!(out > placed);
        assert!(out >= r.profile.exit_at);
        assert!(out >= r.profile.request_at + rules.min_stay_secs);
        for &id in &r.withdrawal_events {
            let e = event(&sim, id);
            assert_eq!((e.kind, e.at_secs), (EventKind::Withdrawal, out));
            assert_eq!((e.from.as_str(), e.to.as_str()), (r.vault.as_str(), rules.account.as_str()));
            *withdrawal_members.entry(id).or_default() += 1;
        }
        let mut paid: BTreeMap<u64, u32> = BTreeMap::new();
        for &id in &r.payment_events {
            let e = event(&sim, id);
            assert_eq!(e.kind, EventKind::ExitPayment);
            assert!(e.at_secs > out && e.at_secs <= out + rules.exit_window_secs);
            assert!(e.at_secs >= r.profile.request_at + rules.min_stay_secs);
            assert_eq!((e.from.as_str(), e.to.as_str()), (rules.account.as_str(), r.account.as_str()));
            *paid.entry(e.denomination).or_default() += e.count;
            payments += 1;
        }
        let wanted: BTreeMap<u64, u32> = r.profile.exit_notes.iter().map(|n| (n.denomination, n.count)).collect();
        assert_eq!(paid, wanted);
    }
    assert!(payments > 0);
    for (id, members) in withdrawal_members {
        assert!(members >= rules.k, "withdrawal {id} serves only {members} requests");
    }
}

#[test]
fn the_minimum_stay_holds_for_users_who_want_to_leave_at_once() {
    let mut c = config(13);
    c.stay_min_secs = 0;
    c.stay_max_secs = 60;
    c.agent.min_wait_secs = 0;
    c.agent.min_stay_secs = 1800;
    let sim = simulate(&c).unwrap();
    let mut exited = 0;
    for r in &sim.truth.requests {
        if let Some(out) = r.withdrawn_at {
            assert!(out >= r.profile.request_at + c.agent.min_stay_secs);
            exited += 1;
        }
    }
    assert!(exited > 0);
}

#[test]
fn partial_exits_take_out_fewer_notes_than_deposited() {
    let (_, sim) = run(5);
    for r in &sim.truth.requests {
        let p = &r.profile;
        let total = |notes: &[ona_crowd::Notes]| notes.iter().map(|n| n.count).sum::<u32>();
        assert!(total(&p.exit_notes) >= 1);
        if p.is_partial() {
            assert!(total(&p.exit_notes) < total(&p.notes));
        } else {
            assert_eq!(p.exit_notes, p.notes);
        }
        for out in &p.exit_notes {
            let held = p.notes.iter().find(|n| n.denomination == out.denomination).expect("exit of a note never held");
            assert!(out.count <= held.count);
        }
    }
}

#[test]
fn the_public_timeline_holds_only_whole_notes() {
    let (c, sim) = run(6);
    let mut last = 0;
    for e in &sim.timeline {
        check_event(&c, e).unwrap();
        assert!(c.denominations.contains(&e.denomination));
        assert_eq!(e.amount, e.denomination * u64::from(e.count));
        assert!(e.at_secs >= last);
        last = e.at_secs;
    }
    let bad = PublicEvent { amount: 15, ..sim.timeline[0].clone() };
    assert!(check_event(&c, &bad).is_err());
    let unlisted = PublicEvent { denomination: 5, count: 1, amount: 5, ..sim.timeline[0].clone() };
    assert!(check_event(&c, &unlisted).is_err());
}

#[test]
fn the_public_timeline_does_not_link_users_to_vaults() {
    let (c, sim) = run(1);
    let json: serde_json::Value = serde_json::to_value(&sim.timeline).unwrap();
    let fields: BTreeSet<String> = json[0].as_object().unwrap().keys().cloned().collect();
    let expected: BTreeSet<String> =
        ["id", "at_secs", "kind", "from", "to", "denomination", "count", "amount"].map(String::from).into();
    assert_eq!(fields, expected);
    let vaults: BTreeSet<&str> = c.vaults.iter().map(|v| v.contract.as_str()).collect();
    for r in &sim.truth.requests {
        for e in sim.timeline.iter().filter(|e| e.from == r.account || e.to == r.account) {
            // A user only ever deals with the mint (deposit) and the agent (exit), never a vault.
            assert!(!vaults.contains(e.from.as_str()) && !vaults.contains(e.to.as_str()));
            match e.kind {
                EventKind::Deposit => assert_eq!((e.from.as_str(), e.to.as_str()), (r.account.as_str(), c.mint_account.as_str())),
                EventKind::ExitPayment => assert_eq!(e.from, c.agent.account),
                other => panic!("a user account appears in a {other:?}"),
            }
        }
    }
}

#[test]
fn exits_never_exceed_what_the_account_deposited() {
    let (_, sim) = run(14);
    let none = BTreeMap::new();
    check_exit_caps(&sim.timeline, &none).unwrap();
    for r in &sim.truth.requests {
        let deposited: u64 = r.deposit_events.iter().map(|&i| sim.timeline[i].amount).sum();
        let paid: u64 = r.payment_events.iter().map(|&i| sim.timeline[i].amount).sum();
        assert!(paid <= deposited);
    }
    use EventKind::*;
    let over = vec![ev(0, Deposit, "a", "mint", 10, 1), ev(2000, ExitPayment, "agent", "a", 100, 1)];
    assert!(check_exit_caps(&over, &none).unwrap_err().to_string().contains("more than"));
    // The cap is deposits plus gains.
    let gains = BTreeMap::from([("a".to_string(), 90)]);
    assert!(check_exit_caps(&over, &gains).is_ok());
    let elsewhere = vec![ev(0, Deposit, "a", "mint", 10, 1), ev(2000, ExitPayment, "agent", "b", 10, 1)];
    assert!(check_exit_caps(&elsewhere, &none).unwrap_err().to_string().contains("never deposited"));
    let before = vec![ev(2000, ExitPayment, "agent", "a", 10, 1), ev(3000, Deposit, "a", "mint", 10, 1)];
    assert!(check_exit_caps(&before, &gains).is_err());
}

fn ev(at_secs: u64, kind: EventKind, from: &str, to: &str, denomination: u64, count: u32) -> PublicEvent {
    PublicEvent {
        id: 0,
        at_secs,
        kind,
        from: from.into(),
        to: to.into(),
        denomination,
        count,
        amount: denomination * u64::from(count),
    }
}

/// Wait 100, stay 900, exit window 300, vaults v1 and v2.
fn hand_config(rules: AgentRules) -> Config {
    Config {
        vaults: vec![
            Vault { kind: VaultKind::Staking, contract: "v1".into() },
            Vault { kind: VaultKind::Staking, contract: "v2".into() },
        ],
        agent: AgentRules { min_wait_secs: 100, min_stay_secs: 900, exit_window_secs: 300, ..rules },
        ..Config::default()
    }
}

/// A consistent world: a and d in v1, b and c in v2. a and c are paid out, b and d are not.
fn hand_case() -> Vec<PublicEvent> {
    use EventKind::*;
    vec![
        ev(0, Deposit, "a", "mint", 100, 2),
        ev(0, Deposit, "b", "mint", 100, 1),
        ev(0, Deposit, "d", "mint", 100, 1),
        ev(500, Deposit, "c", "mint", 100, 2),
        ev(200, Placement, "agent", "v1", 100, 3),
        ev(300, Placement, "agent", "v2", 100, 1),
        ev(700, Placement, "agent", "v2", 100, 2),
        ev(1000, Withdrawal, "v1", "agent", 100, 2),
        ev(1100, ExitPayment, "agent", "a", 100, 1),
        ev(1200, ExitPayment, "agent", "a", 100, 1),
        ev(1600, Withdrawal, "v2", "agent", 100, 2),
        ev(1700, ExitPayment, "agent", "c", 100, 1),
        ev(1800, ExitPayment, "agent", "c", 100, 1),
    ]
}

#[test]
fn vault_privacy_on_a_case_counted_by_hand() {
    let p = privacy(&hand_case(), &hand_config(AgentRules::default()));
    assert!(p.joint);
    // a: batches from 100 holding two notes are v1 at 200 and v2 at 700, but a was paid at 1100 and
    //    1200 and only v1 withdrew before (at 1000): v1, one batch.
    // c: from 600 on, only v2 at 700 holds two notes, and v2 withdrew at 1600: v2, one batch.
    // b and d: one note each, so v1 at 200, v2 at 300 or v2 at 700 alone; but c fills v2 at 700
    //    (two of two notes), so neither fits there: both vaults, two batches each.
    // Order of first deposit: a, b, d (all at 0, by name), then c.
    assert_eq!(p.vaults.sizes, vec![1, 2, 2, 1]);
    assert_eq!(p.batches.sizes, vec![1, 2, 2, 1]);
    assert_eq!((p.exposed, p.unmatched), (2, 0));
    assert_eq!((p.vaults.median, p.vaults.minimum), (Some(1.5), Some(1)));
}

#[test]
fn joint_assignment_narrows_what_each_account_alone_allows() {
    // Noise turns the joint assignment off, which leaves the per-account bound: b and d could also
    // be in v2 at 700.
    let alone = privacy(&hand_case(), &hand_config(AgentRules { noise_moves_per_hour: 6, ..AgentRules::default() }));
    assert!(!alone.joint);
    assert_eq!(alone.batches.sizes, vec![1, 3, 3, 1]);
}

#[test]
fn batch_composition_forces_the_assignment() {
    // Two batches at the same moment. u3 and u4 alone hold notes of 1, and batch v2 holds exactly
    // two, so both are in v2; that fills its two notes of 100, which pushes u1 and u2 into v1.
    use EventKind::*;
    let mut timeline = vec![
        ev(0, Deposit, "u1", "mint", 100, 1),
        ev(0, Deposit, "u2", "mint", 100, 1),
        ev(0, Deposit, "u3", "mint", 100, 1),
        ev(0, Deposit, "u3", "mint", 1, 1),
        ev(0, Deposit, "u4", "mint", 100, 1),
        ev(0, Deposit, "u4", "mint", 1, 1),
        ev(200, Placement, "agent", "v1", 100, 2),
        ev(200, Placement, "agent", "v2", 100, 2),
        ev(200, Placement, "agent", "v2", 1, 2),
    ];
    let joint = privacy(&timeline, &hand_config(AgentRules::default()));
    assert_eq!((joint.vaults.sizes.clone(), joint.exposed), (vec![1, 1, 1, 1], 4));
    let alone = privacy(&timeline, &hand_config(AgentRules { noise_moves_per_hour: 6, ..AgentRules::default() }));
    assert_eq!((alone.vaults.sizes.clone(), alone.exposed), (vec![2, 2, 1, 1], 2));

    // An account with no possible batch was never placed: it is counted apart, not as a minimum.
    timeline.push(ev(0, Deposit, "u5", "mint", 100, 4));
    let p = privacy(&timeline, &hand_config(AgentRules::default()));
    assert_eq!((p.unmatched, p.vaults.sizes.len()), (1, 4));
    let none = privacy(&[], &hand_config(AgentRules::default()));
    assert_eq!((none.vaults.median, none.batches.minimum, none.exposed), (None, None, 0));
}

#[test]
fn with_a_reserve_only_the_kept_amount_counts() {
    // 20 % reserve: a deposit of 100 places at least 80, cut into any notes.
    use EventKind::*;
    let timeline = vec![
        ev(0, Deposit, "a", "mint", 100, 1),
        ev(200, Placement, "agent", "v1", 10, 7),
        ev(300, Placement, "agent", "v2", 10, 8),
    ];
    let c = hand_config(AgentRules { reserve_percent: 20, ..AgentRules::default() });
    let (found, joint) = candidates(&timeline, &c);
    assert!(!joint);
    assert_eq!(found[0].vaults, BTreeSet::from(["v2".to_string()]));
}

#[test]
fn with_net_settlement_every_vault_stays_possible() {
    let c = hand_config(AgentRules { settlement_period_secs: 1800, ..AgentRules::default() });
    let p = privacy(&hand_case(), &c);
    assert_eq!(p.vaults.sizes, vec![2, 2, 2, 2]);
    assert_eq!(p.exposed, 0);
}

fn with_parades(seed: u64, reserve: u8, period: u64, noise: u32) -> Config {
    let mut c = config(seed);
    c.run_secs = 6 * 3600;
    c.agent.reserve_percent = reserve;
    c.agent.settlement_period_secs = period;
    c.agent.noise_moves_per_hour = noise;
    c
}

fn all_scenarios(seed: u64) -> Vec<Config> {
    vec![
        with_parades(seed, 0, 0, 0),
        with_parades(seed, 20, 0, 0),
        with_parades(seed, 0, 1800, 0),
        with_parades(seed, 0, 0, 12),
        with_parades(seed, 20, 1800, 0),
        with_parades(seed, 20, 1800, 12),
    ]
}

#[test]
fn every_countermeasure_keeps_the_books_straight() {
    for c in all_scenarios(5) {
        let sim = simulate(&c).unwrap();
        // Never overdraws the reserve or a vault, never pays more than an account deposited.
        execute(&sim, &c, &mut MemoryChain::default(), &mut |_| {}).unwrap();
        for e in &sim.timeline {
            check_event(&c, e).unwrap();
        }
        // Every request that left was paid in full.
        for r in sim.truth.requests.iter().filter(|r| r.withdrawn_at.is_some()) {
            let paid: u64 = r.payment_events.iter().map(|&i| sim.timeline[i].amount).sum();
            let wanted: u64 = r.profile.exit_notes.iter().map(|n| n.denomination * u64::from(n.count)).sum();
            assert_eq!(paid, wanted, "{:?}", c.agent);
        }
    }
}

#[test]
fn net_settlement_moves_funds_only_at_fixed_times_and_one_way_per_vault() {
    let c = with_parades(6, 0, 1800, 0);
    let sim = simulate(&c).unwrap();
    let mut directions: BTreeMap<(u64, String), BTreeSet<bool>> = BTreeMap::new();
    for e in sim.timeline.iter().filter(|e| matches!(e.kind, EventKind::Placement | EventKind::Withdrawal)) {
        assert_eq!(e.at_secs % 1800, 0, "a move outside settlement: {e:?}");
        let vault = if e.kind == EventKind::Placement { e.to.clone() } else { e.from.clone() };
        directions.entry((e.at_secs, vault)).or_default().insert(e.kind == EventKind::Placement);
    }
    assert!(!directions.is_empty());
    assert!(directions.values().all(|kinds| kinds.len() == 1), "a vault both received and sent at one settlement");
}

#[test]
fn with_a_reserve_exits_do_not_wait_for_a_vault_withdrawal() {
    let c = with_parades(7, 20, 0, 0);
    let sim = simulate(&c).unwrap();
    let withdrawals: Vec<u64> =
        sim.timeline.iter().filter(|e| e.kind == EventKind::Withdrawal).map(|e| e.at_secs).collect();
    let payments: Vec<u64> = sim.timeline.iter().filter(|e| e.kind == EventKind::ExitPayment).map(|e| e.at_secs).collect();
    let unprompted = payments
        .iter()
        .filter(|&&p| !withdrawals.iter().any(|&w| w <= p && p <= w + c.agent.exit_window_secs))
        .count();
    assert!(unprompted > 0, "every payment still follows a withdrawal");
    assert!(withdrawals.len() < sim.truth.requests.iter().filter(|r| r.withdrawn_at.is_some()).count());

    // At every placement, the vaults hold at most 80 % of the funds, give or take one note.
    let (mut reserve, mut placed) = (0i64, 0i64);
    for e in &sim.timeline {
        match e.kind {
            EventKind::Deposit => reserve += e.amount as i64,
            EventKind::Placement => {
                reserve -= e.amount as i64;
                placed += e.amount as i64;
                assert!(placed * 100 <= (placed + reserve) * 80 + 100 * 100, "reserve fell below 20 %");
            }
            EventKind::Withdrawal => {
                reserve += e.amount as i64;
                placed -= e.amount as i64;
            }
            EventKind::ExitPayment => reserve -= e.amount as i64,
            EventKind::Yield => placed += e.amount as i64,
        }
    }
}

#[test]
fn noise_adds_round_trips_and_their_cost() {
    let quiet = simulate(&with_parades(8, 0, 0, 0)).unwrap();
    let noisy_config = with_parades(8, 0, 0, 12);
    let noisy = simulate(&noisy_config).unwrap();
    assert!(agent_transactions(&noisy.timeline) > agent_transactions(&quiet.timeline));
    // Every lent note comes back: what the vaults hold in the end is what the requests left there.
    let net = |s: &Simulation| {
        s.timeline.iter().fold(0i64, |acc, e| match e.kind {
            EventKind::Placement => acc + e.amount as i64,
            EventKind::Withdrawal => acc - e.amount as i64,
            _ => acc,
        })
    };
    let owed = |s: &Simulation| {
        let amount = |notes: &[ona_crowd::Notes]| notes.iter().map(|n| (n.denomination * u64::from(n.count)) as i64).sum::<i64>();
        s.truth.requests.iter().fold(0i64, |acc, r| {
            let placed = if r.placed_at.is_some() { amount(&r.profile.notes) } else { 0 };
            let left = if r.withdrawn_at.is_some() { amount(&r.profile.exit_notes) } else { 0 };
            acc + placed - left
        })
    };
    assert_eq!(net(&quiet), owed(&quiet));
    assert_eq!(net(&noisy), owed(&noisy));
    execute(&noisy, &noisy_config, &mut MemoryChain::default(), &mut |_| {}).unwrap();
}

#[test]
fn countermeasures_off_change_nothing() {
    let mut off = config(3);
    off.agent.reserve_percent = 0;
    off.agent.settlement_period_secs = 0;
    off.agent.noise_moves_per_hour = 0;
    assert_eq!(simulate(&off).unwrap().timeline, simulate(&config(3)).unwrap().timeline);
    assert!(off.agent.direct_exit());
    let bad = Config { agent: AgentRules { reserve_percent: 95, ..AgentRules::default() }, ..config(3) };
    assert!(simulate(&bad).is_err());
    let lonely = Config {
        vaults: vec![Vault { kind: VaultKind::Staking, contract: "s.testnet".into() }],
        agent: AgentRules { noise_moves_per_hour: 6, ..AgentRules::default() },
        ..config(3)
    };
    assert!(simulate(&lonely).err().expect("refused").to_string().contains("two vaults"));
}

#[test]
fn the_comparison_covers_every_scenario() {
    let mut base = config(1);
    base.users = 30;
    base.run_secs = 6 * 3600;
    let rows = compare(&base, &scenarios(20, 1800, 12), 2).unwrap();
    assert_eq!(rows.len(), 8);
    assert!(rows[0].joint && !rows[1].joint);
    for r in &rows {
        assert!((0.0..=1.0).contains(&r.exposed_share));
        for g in [r.worst_max, r.observer_success, r.blind, r.last_withdrawal_guess].into_iter().flatten() {
            assert!((0.0..=1.0).contains(&g));
        }
        assert!(r.mean_entropy_bits.unwrap() >= 0.0 && r.mean_entropy_bits.unwrap() <= 1.0 + 1e-9);
        assert_eq!((r.yield_guess, r.yield_lost), (None, None));
    }
    // Net settlement ties no account to a vault.
    assert_eq!(rows[2].exposed_share, 0.0);
    let text = table(&rows);
    assert_eq!(text.lines().count(), 10);
    assert!(text.lines().nth(2).unwrap().contains("| +0 |"));
    let g = guesses(&simulate(&base).unwrap(), &base);
    assert!(g.most_chosen.unwrap() >= 0.5);
}

fn route(account: &str, vault: &str, placed_at: u64) -> TrueRoute {
    TrueRoute {
        account: account.into(),
        vault: Some(vault.into()),
        first_vault: Some(vault.into()),
        placed_at: Some(placed_at),
        withdrawn_at: None,
        switched_at: None,
        placed: 0,
        principal_out: 0,
    }
}

#[test]
fn posterior_of_four_identical_users_is_an_even_split() {
    // Two batches of two notes of 100, four users with one note each: any two can be in either
    // batch, so each user is in v1 with probability 1/2.
    use EventKind::*;
    let timeline = vec![
        ev(0, Deposit, "u1", "mint", 100, 1),
        ev(0, Deposit, "u2", "mint", 100, 1),
        ev(0, Deposit, "u3", "mint", 100, 1),
        ev(0, Deposit, "u4", "mint", 100, 1),
        ev(200, Placement, "agent", "v1", 100, 2),
        ev(200, Placement, "agent", "v2", 100, 2),
    ];
    let truth = vec![route("u1", "v1", 200), route("u2", "v1", 200), route("u3", "v2", 200), route("u4", "v2", 200)];
    let p = posterior_from(&timeline, &hand_config(AgentRules::default()), &truth, &[], 2000);
    assert_eq!(p.users, 4);
    assert!((p.worst_max.unwrap() - 0.5).abs() < 0.06, "{p:?}");
    assert!((p.mean_entropy_bits.unwrap() - 1.0).abs() < 0.02, "{p:?}");
    assert_eq!(p.blind, Some(0.5));
}

#[test]
fn posterior_with_one_distinct_user() {
    // u1 alone holds a note of 1, so it is certainly in v2. The other three hold one note of 100:
    // one of them is in v2 with u1, two in v1, so each is in v2 with probability 1/3.
    // Worst user: 1. Entropy: (0 + 3 x 0.918) / 4 = 0.689 bit. An observer guessing the most
    // probable vault finds u1 and the two users in v1: 3 of 4.
    use EventKind::*;
    let timeline = vec![
        ev(0, Deposit, "u1", "mint", 1, 1),
        ev(0, Deposit, "u2", "mint", 100, 1),
        ev(0, Deposit, "u3", "mint", 100, 1),
        ev(0, Deposit, "u4", "mint", 100, 1),
        ev(200, Placement, "agent", "v1", 100, 2),
        ev(200, Placement, "agent", "v2", 100, 1),
        ev(200, Placement, "agent", "v2", 1, 1),
    ];
    let truth = vec![route("u1", "v2", 200), route("u2", "v1", 200), route("u3", "v1", 200), route("u4", "v2", 200)];
    let p = posterior_from(&timeline, &hand_config(AgentRules::default()), &truth, &[], 3000);
    assert_eq!(p.worst_max, Some(1.0));
    assert!((p.mean_entropy_bits.unwrap() - 0.689).abs() < 0.03, "{p:?}");
    assert!((p.success.unwrap() - 0.75).abs() < 1e-9, "{p:?}");
}

#[test]
fn the_sampler_never_leaves_assignments_that_explain_the_timeline() {
    // Without any user that can be swapped, the observer is certain of everyone.
    use EventKind::*;
    let timeline = vec![
        ev(0, Deposit, "u1", "mint", 1, 1),
        ev(0, Deposit, "u2", "mint", 100, 1),
        ev(200, Placement, "agent", "v1", 1, 1),
        ev(200, Placement, "agent", "v2", 100, 1),
    ];
    let truth = vec![route("u1", "v1", 200), route("u2", "v2", 200)];
    let p = posterior_from(&timeline, &hand_config(AgentRules::default()), &truth, &[], 500);
    assert_eq!((p.worst_max, p.mean_entropy_bits, p.success), (Some(1.0), Some(0.0), Some(1.0)));
}

#[test]
fn accounts_with_different_deposits_are_never_swapped() {
    // w (two notes) fits batch v1 and u (one note) fits batch v2, but swapping them would put three
    // notes in v1, which holds two. Only u and x, with identical deposits, may trade places, and they
    // share v1 anyway: everyone is certain.
    use EventKind::*;
    let timeline = vec![
        ev(0, Deposit, "u", "mint", 100, 1),
        ev(0, Deposit, "w", "mint", 100, 2),
        ev(0, Deposit, "x", "mint", 100, 1),
        ev(200, Placement, "agent", "v1", 100, 2),
        ev(200, Placement, "agent", "v2", 100, 2),
    ];
    let truth = vec![route("u", "v1", 200), route("w", "v2", 200), route("x", "v1", 200)];
    let p = posterior_from(&timeline, &hand_config(AgentRules::default()), &truth, &[], 1000);
    assert_eq!((p.worst_max, p.mean_entropy_bits, p.success), (Some(1.0), Some(0.0), Some(1.0)));
}

#[test]
fn the_posterior_is_never_more_private_than_the_elimination_bound() {
    for c in all_scenarios(4) {
        let sim = simulate(&c).unwrap();
        let p = posterior(&sim, &c, 100);
        let bound = privacy(&sim.timeline, &c);
        // A user certain under elimination stays certain under sampling.
        if bound.exposed > 0 {
            assert_eq!(p.worst_max, Some(1.0), "{:?}", c.agent);
        }
        assert!(p.success.unwrap() >= p.blind.unwrap() - 0.2);
    }
}

#[test]
fn every_sampled_state_replays_the_public_timeline() {
    let mut configs = all_scenarios(5);
    let mut separate = with_parades(5, 20, 1800, 0);
    separate.agent.min_active_per_settlement = 10;
    configs.push(separate.clone());
    separate.agent.switch_percent = 30;
    configs.push(separate);
    let mut with_yield = yield_config(5);
    with_yield.agent.reserve_percent = 20;
    with_yield.agent.settlement_period_secs = 1800;
    configs.push(with_yield.clone());
    with_yield.agent.reserve_percent = 0;
    with_yield.agent.settlement_period_secs = 0;
    configs.push(with_yield);
    for c in configs {
        let sim = simulate(&c).unwrap();
        let p = posterior(&sim, &c, 200);
        assert!(p.replayed > 0);
        assert_eq!(p.replay_failures, 0, "{:?}", c.agent);
        assert!(p.frozen <= p.users);
        if p.frozen > 0 {
            assert_eq!(p.worst_max, Some(1.0), "a frozen user is always certain");
        }
    }
}

#[test]
fn the_replay_catches_an_inconsistent_swap() {
    // u and w have different deposits. If the sampler swapped them, the batches would no longer hold
    // their members' notes; with identical deposits it may.
    use EventKind::*;
    let timeline = vec![
        ev(0, Deposit, "u", "mint", 100, 1),
        ev(0, Deposit, "w", "mint", 100, 2),
        ev(0, Deposit, "x", "mint", 100, 1),
        ev(200, Placement, "agent", "v1", 100, 2),
        ev(200, Placement, "agent", "v2", 100, 2),
    ];
    let truth = vec![route("u", "v1", 200), route("w", "v2", 200), route("x", "v1", 200)];
    let p = posterior_from(&timeline, &hand_config(AgentRules::default()), &truth, &[], 500);
    assert_eq!((p.replay_failures, p.frozen), (0, 1));
}

fn yield_config(seed: u64) -> Config {
    Config {
        seed,
        users: 60,
        run_secs: 6 * 3600,
        partial_exit_percent: 0,
        vaults: vec![
            Vault { kind: VaultKind::Staking, contract: "stake-a.testnet".into() },
            Vault { kind: VaultKind::Staking, contract: "stake-b.testnet".into() },
            Vault { kind: VaultKind::Lending, contract: "lend-c.testnet".into() },
            Vault { kind: VaultKind::Lending, contract: "lend-d.testnet".into() },
        ],
        vault_weights: vec![3, 1, 3, 1],
        yield_bp_per_hour: vec![100, 200, 300, 600],
        ..Config::default()
    }
}

#[test]
fn individual_yield_pays_each_vault_rate_in_whole_notes() {
    let c = yield_config(1);
    let sim = simulate(&c).unwrap();
    execute(&sim, &c, &mut MemoryChain::default(), &mut |_| {}).unwrap();
    let mut gained = 0;
    for r in sim.truth.requests.iter().filter(|r| r.withdrawn_at.is_some()) {
        let v = c.vaults.iter().position(|x| x.contract == r.vault).unwrap();
        let principal = r.profile.exit_notes.iter().map(|n| n.denomination * u64::from(n.count)).sum::<u64>();
        let duration = r.withdrawn_at.unwrap() - r.placed_at.unwrap();
        assert_eq!(r.gain, principal * c.yield_of(v) * duration / 36_000_000);
        assert!(r.gain_paid <= r.gain && r.gain - r.gain_paid < 1, "only what notes cannot make stays");
        gained += r.gain_paid;
    }
    assert!(gained > 0);
    assert!(sim.timeline.iter().any(|e| e.kind == EventKind::Yield));
    for e in &sim.timeline {
        check_event(&c, e).unwrap();
    }
}

#[test]
fn pooled_yield_gives_everyone_the_same_rate_and_hides_the_vault() {
    // Large deposits (four notes of 100) and notes of 1 to pay gains, so the rate shows.
    let mut pooled = yield_config(2);
    pooled.denominations = vec![1, 100];
    pooled.notes_per_denomination = vec![4];
    pooled.yield_mode = ona_crowd::YieldMode::Pooled;
    let individual = Config { yield_mode: ona_crowd::YieldMode::Individual, ..pooled.clone() };
    let pooled_guess = yield_guess(&simulate(&pooled).unwrap(), &pooled).unwrap();
    let individual_guess = yield_guess(&simulate(&individual).unwrap(), &individual).unwrap();
    assert!(individual_guess > pooled_guess + 0.2, "individual {individual_guess}, pooled {pooled_guess}");
    assert_eq!(yield_guess(&simulate(&config(2)).unwrap(), &config(2)), None);
}

#[test]
fn suggestions_move_users_to_the_most_popular_vault_of_the_same_kind() {
    let mut c = yield_config(3);
    c.suggestion_percent = 100;
    let sim = simulate(&c).unwrap();
    for r in &sim.truth.requests {
        let p = &r.profile;
        assert_eq!(p.vault, c.most_popular_like(p.wanted_vault));
        assert_eq!(c.vaults[p.vault].kind, c.vaults[p.wanted_vault].kind);
        assert!(p.vault == 0 || p.vault == 2);
        if r.withdrawn_at.is_some() && p.vault != p.wanted_vault {
            assert!(r.wanted_gain >= r.gain, "a suggestion moves to a lower rate here");
        }
    }
    assert!(sim.truth.requests.iter().any(|r| r.profile.vault != r.profile.wanted_vault));
    c.suggestion_percent = 0;
    assert!(simulate(&c).unwrap().truth.requests.iter().all(|r| r.profile.vault == r.profile.wanted_vault));
}

#[test]
fn a_settlement_waits_for_enough_active_requests() {
    let mut c = with_parades(6, 20, 600, 0);
    c.agent.min_active_per_settlement = 1000;
    let sim = simulate(&c).unwrap();
    // With an unreachable threshold, nothing moves before the agent stops acting.
    assert!(sim
        .timeline
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Placement | EventKind::Withdrawal))
        .all(|e| e.at_secs > c.run_secs));
    execute(&sim, &c, &mut MemoryChain::default(), &mut |_| {}).unwrap();
    c.agent.min_active_per_settlement = 0;
    let eager = simulate(&c).unwrap();
    assert!(eager.timeline.iter().any(|e| e.kind == EventKind::Placement && e.at_secs <= c.run_secs));
}

#[test]
fn steady_withdrawals_leave_every_vault_at_a_fixed_pace() {
    let mut c = with_parades(9, 20, 1800, 0);
    c.agent.steady_withdrawal_period_secs = 600;
    c.agent.steady_withdrawal_units = 10;
    let sim = simulate(&c).unwrap();
    for (v, vault) in c.vaults.iter().enumerate() {
        let times: BTreeSet<u64> = sim
            .timeline
            .iter()
            .filter(|e| e.kind == EventKind::Withdrawal && e.from == vault.contract && e.at_secs % 1800 != 0)
            .map(|e| e.at_secs)
            .collect();
        assert!(!times.is_empty(), "vault {v} never withdrew steadily");
        assert!(times.iter().all(|t| t % 600 == 0));
    }
    execute(&sim, &c, &mut MemoryChain::default(), &mut |_| {}).unwrap();
    let mut alone = with_parades(9, 20, 0, 0);
    alone.agent.steady_withdrawal_period_secs = 600;
    assert!(simulate(&alone).err().unwrap().to_string().contains("net settlement"));
}

#[test]
fn a_switch_moves_a_placed_request_to_another_vault_without_an_exit() {
    let mut c = with_parades(10, 20, 1800, 0);
    c.agent.switch_percent = 100;
    let sim = simulate(&c).unwrap();
    let moved: Vec<_> = sim.truth.requests.iter().filter(|r| r.vault != r.first_vault).collect();
    assert!(!moved.is_empty());
    for r in &moved {
        let s = r.profile.switch.unwrap();
        assert_eq!(r.vault, c.vaults[s.to].contract);
        assert!(r.placed_at.is_some(), "only a placed request can switch");
        // The user's own account sees nothing of it.
        assert!(r.payment_events.iter().all(|&i| sim.timeline[i].kind == EventKind::ExitPayment));
    }
    execute(&sim, &c, &mut MemoryChain::default(), &mut |_| {}).unwrap();
    let mut direct = with_parades(10, 0, 0, 0);
    direct.agent.switch_percent = 30;
    assert!(simulate(&direct).is_err());
}

#[test]
fn bad_yield_settings_are_refused() {
    let mut c = yield_config(1);
    c.yield_bp_per_hour = vec![1, 2];
    assert!(simulate(&c).err().unwrap().to_string().contains("one value per vault"));
    let mut c = yield_config(1);
    c.vault_weights = vec![0, 0, 0, 0];
    assert!(simulate(&c).is_err());
    let mut c = yield_config(1);
    c.suggestion_percent = 101;
    assert!(simulate(&c).is_err());
}

#[test]
fn the_true_vault_is_never_excluded_whatever_the_countermeasures() {
    for seed in [9, 21, 33] {
        for c in all_scenarios(seed) {
            let sim = simulate(&c).unwrap();
            let (found, _) = candidates(&sim.timeline, &c);
            let by_account: BTreeMap<&str, &ona_crowd::Candidates> = found.iter().map(|f| (f.account.as_str(), f)).collect();
            for r in sim.truth.requests.iter().filter(|r| r.placed_at.is_some()) {
                let f = by_account[r.account.as_str()];
                assert!(f.vaults.contains(&r.vault), "seed {seed}, {:?}: true vault excluded for {}", c.agent, r.account);
                // With net settlement a placement can be cancelled out by withdrawals: no batch to see.
                if c.agent.direct_placement() {
                    assert!(f.batches >= 1);
                }
            }
        }
    }
}

#[test]
fn the_timeline_plays_on_the_memory_chain() {
    let (c, sim) = run(10);
    let mut chain = MemoryChain::default();
    let mut waited = 0;
    execute(&sim, &c, &mut chain, &mut |s| waited += s).unwrap();
    assert_eq!(waited, sim.timeline.last().unwrap().at_secs);

    let deposited: u64 = sim.timeline.iter().filter(|e| e.kind == EventKind::Deposit).map(|e| e.amount).sum();
    let paid: u64 = sim.timeline.iter().filter(|e| e.kind == EventKind::ExitPayment).map(|e| e.amount).sum();
    let in_vaults: u64 = chain.vaults.values().sum();
    assert_eq!(chain.reserve + in_vaults + paid, deposited);
    for r in &sim.truth.requests {
        // Funded with exactly its deposits, which all left: what remains is what came back.
        let wanted: u64 = r.profile.exit_notes.iter().map(|n| n.denomination * u64::from(n.count)).sum();
        let got = chain.balances.get(&r.account).copied().unwrap_or(0);
        assert_eq!(got, if r.withdrawn_at.is_some() { wanted } else { 0 });
    }
}

#[test]
fn a_timeline_that_overdraws_is_refused() {
    let (c, mut sim) = run(11);
    // A withdrawal from a vault before anything was placed in it.
    let first = sim.timeline.iter().position(|e| e.kind == EventKind::Withdrawal).unwrap();
    let mut early = sim.timeline[first].clone();
    early.at_secs = 0;
    sim.timeline.insert(0, early);
    let error = execute(&sim, &c, &mut MemoryChain::default(), &mut |_| {}).unwrap_err();
    assert!(error.to_string().contains("vault does not hold"), "{error}");
}

#[test]
fn bad_configurations_are_refused() {
    type Mutation = (fn(&mut Config), &'static str);
    let mutations: Vec<Mutation> = vec![
        (|c| c.agent.k = 1, "k must be at least 2"),
        (|c| c.notes_per_denomination = vec![1, 3], "powers of two"),
        (|c| c.notes_per_denomination = vec![128], "powers of two"),
        (|c| c.vaults.clear(), "list of vaults"),
        (|c| c.vaults[0].contract = "Not An Account".into(), "not a NEAR account"),
        (|c| c.denominations = vec![1, 1], "listed twice"),
        (|c| c.denominations = vec![0], "positive"),
        (|c| c.users = 0, "one user"),
        (|c| c.stay_min_secs = c.stay_max_secs + 1, "stay_min_secs"),
        (|c| c.agent.window_secs = 0, "windows"),
        (|c| c.run_secs = 10, "deposit window"),
    ];
    for (mutate, message) in mutations {
        let mut c = config(1);
        mutate(&mut c);
        let error = simulate(&c).err().expect("must be refused").to_string();
        assert!(error.contains(message), "{error:?} should mention {message:?}");
    }
    let unknown = r#"{"vaults":[{"kind":"staking","contract":"s.testnet"}],"surprise":1}"#;
    assert!(serde_json::from_str::<Config>(unknown).is_err());
    let minimal = r#"{"vaults":[{"kind":"staking","contract":"s.testnet"}]}"#;
    assert!(simulate(&serde_json::from_str::<Config>(minimal).unwrap()).is_ok());
}

#[test]
fn keys_go_to_a_private_new_file_and_are_never_shown() {
    let (_, sim) = run(12);
    let path = temp_path("keys");
    write_keys(&path, &sim.users).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(write_keys(&path, &sim.users).is_err(), "an existing key file must not be replaced");

    let entries: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(entries.len(), sim.users.len());
    for (entry, user) in entries.iter().zip(&sim.users) {
        let key = ona_near::parse_account_key(entry["secret_key"].as_str().unwrap()).unwrap();
        assert_eq!(implicit_account(&key), entry["account"].as_str().unwrap());
        assert_eq!(implicit_account(&key), user.account());
        assert_eq!(entry.as_object().unwrap().len(), 2);
        let shown = format!("{user:?}");
        assert!(!shown.contains(entry["secret_key"].as_str().unwrap().trim_start_matches("ed25519:")));
        assert!(shown.contains(&user.account()));
    }
    std::fs::remove_file(&path).unwrap();
}

fn settings(network: &str, rpc_url: &str) -> NearSettings {
    NearSettings {
        rpc_url: rpc_url.into(),
        network: network.into(),
        mint: "mint.example.testnet".into(),
        funder_account: "funder.example.testnet".into(),
        agent_account: "agent.example.testnet".into(),
        unit_yocto: 100_000_000_000_000_000_000_000,
    }
}

#[test]
fn mainnet_is_refused_before_any_call() {
    let staking = [Vault { kind: VaultKind::Staking, contract: "s.testnet".into() }];
    for (network, rpc) in [
        ("mainnet", "https://rpc.testnet.near.org"),
        ("testnet", "https://rpc.mainnet.near.org"),
        ("", "http://127.0.0.1:3030"),
    ] {
        assert!(check_settings(&settings(network, rpc), &staking).is_err());
        let tokens = temp_path("tokens-mainnet");
        let key = || SigningKey::from_bytes(&[3u8; 32]);
        let refused = NearChain::connect(settings(network, rpc), key(), key(), &[1], &staking, &tokens);
        assert!(refused.is_err());
        assert!(!tokens.exists(), "nothing may be created before the network is accepted");
    }
    assert!(check_settings(&settings("testnet", "https://rpc.testnet.near.org"), &staking).is_ok());
    assert!(check_settings(&settings("sandbox", "http://127.0.0.1:3030"), &staking).is_ok());
}

#[test]
fn the_chain_id_reported_by_the_node_is_checked() {
    assert!(check_chain_id("testnet", "testnet").is_ok());
    assert!(check_chain_id("sandbox", "localnet").is_ok());
    assert!(check_chain_id("sandbox", "mainnet").is_err());
    assert!(check_chain_id("testnet", "mainnet").is_err());
    assert!(check_chain_id("local", "MAINNET").is_err());
    assert!(check_chain_id("testnet", "localnet").is_err());
    assert!(check_chain_id("sandbox", "").is_err());
}

#[test]
fn lending_vaults_and_a_zero_unit_are_refused_on_near() {
    let lending = [Vault { kind: VaultKind::Lending, contract: "l.testnet".into() }];
    let error = check_settings(&settings("testnet", "https://rpc.testnet.near.org"), &lending).unwrap_err();
    assert!(error.to_string().contains("lending"));
    let staking = [Vault { kind: VaultKind::Staking, contract: "s.testnet".into() }];
    let mut zero = settings("testnet", "https://rpc.testnet.near.org");
    zero.unit_yocto = 0;
    assert!(check_settings(&zero, &staking).is_err());
}
