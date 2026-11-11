//! `ona-crowd simulate <config.json> <out-dir>` runs the simulation offline.
//! `ona-crowd run <config.json> <out-dir>` also plays it on a local NEAR node or testnet, configured
//! by the environment variables in `docs/INSTALL.md`. Mainnet is refused.
//!
//! Both write `timeline.json` (public), `truth.json` (the vault each user chose) and
//! `keys.json` (private keys, created readable by its owner only). Keys are never printed.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ona_crowd::chain::{execute, Chain};
use ona_crowd::near::{check_settings, NearChain, NearSettings};
use ona_crowd::parades::{compare, scenarios, table};
use ona_crowd::{privacy, simulate, simulate_secret, write_keys, Config, EventKind, Simulation};
use ona_near::load_account_key;
use rand::rngs::OsRng;
use rand::RngCore;

const MILLI_NEAR: u128 = 1_000_000_000_000_000_000_000;

fn env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| anyhow!("{name} is not set"))
}

fn env_number<T: std::str::FromStr>(name: &str, default: T) -> Result<T> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| anyhow!("{name} is not a number")),
        Err(_) => Ok(default),
    }
}

fn read_config(path: &str) -> Result<Config> {
    let text = fs::read_to_string(path).with_context(|| format!("cannot read {path}"))?;
    serde_json::from_str(&text).with_context(|| format!("{path} is not a valid configuration"))
}

fn write_outputs(sim: &Simulation, config: &Config, dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    write_keys(&dir.join("keys.json"), &sim.users)?;
    fs::write(dir.join("timeline.json"), serde_json::to_string_pretty(&sim.timeline)?)?;
    fs::write(dir.join("truth.json"), serde_json::to_string_pretty(&sim.truth)?)?;

    let count = |kind| sim.timeline.iter().filter(|e| e.kind == kind).count();
    let exited = sim.truth.requests.iter().filter(|r| r.withdrawn_at.is_some()).count();
    println!(
        "{} users, {} exited by the end; {} deposits, {} placements, {} withdrawals, {} exit payments",
        sim.users.len(),
        exited,
        count(EventKind::Deposit),
        count(EventKind::Placement),
        count(EventKind::Withdrawal),
        count(EventKind::ExitPayment),
    );
    let p = privacy(&sim.timeline, config);
    println!("upper bounds: a stronger observer can narrow these further");
    for (label, sizes) in [("vaults", &p.vaults), ("placement batches", &p.batches)] {
        match (sizes.median, sizes.minimum) {
            (Some(median), Some(minimum)) => println!("possible {label} per placed user: median {median}, minimum {minimum}"),
            _ => println!("possible {label} per placed user: nothing to measure"),
        }
    }
    println!(
        "users whose vault is certain: {} of {} placed ({} never placed)",
        p.exposed,
        p.vaults.sizes.len(),
        p.unmatched
    );
    Ok(())
}

fn run_parades(config_path: &str, seeds: &str) -> Result<()> {
    let config = read_config(config_path)?;
    let seeds: u64 = seeds.parse().map_err(|_| anyhow!("seeds must be a number"))?;
    let rules = &config.agent;
    let set = scenarios(
        if rules.reserve_percent == 0 { 20 } else { rules.reserve_percent },
        if rules.settlement_period_secs == 0 { 1800 } else { rules.settlement_period_secs },
        if rules.noise_moves_per_hour == 0 { 12 } else { rules.noise_moves_per_hour },
    );
    let rows = compare(&config, &set, seeds)?;
    print!("{}", table(&rows));
    println!("\n{} users, {} vaults, seeds 1 to {seeds}. * = per-account bound only (no joint assignment).", config.users, config.vaults.len());
    Ok(())
}

fn run_offline(config_path: &str, dir: &str) -> Result<()> {
    let config = read_config(config_path)?;
    let sim = simulate(&config)?;
    write_outputs(&sim, &config, &PathBuf::from(dir))
}

fn run_on_near(config_path: &str, dir: &str) -> Result<()> {
    let mut config = read_config(config_path)?;
    let settings = NearSettings {
        rpc_url: env("ONA_RPC_URL")?,
        network: env("ONA_NETWORK")?,
        mint: env("ONA_MINT")?,
        funder_account: env("ONA_CROWD_FUNDER_ACCOUNT")?,
        agent_account: env("ONA_CROWD_AGENT_ACCOUNT")?,
        unit_yocto: env_number::<u128>("ONA_CROWD_UNIT_MILLI_NEAR", 100)? * MILLI_NEAR,
    };
    check_settings(&settings, &config.vaults)?;
    config.mint_account = settings.mint.clone();
    config.agent.account = settings.agent_account.clone();
    let speed: u64 = env_number("ONA_CROWD_SPEED", 1)?;

    let funder_key = load_account_key(&PathBuf::from(env("ONA_CROWD_FUNDER_KEY_FILE")?))?;
    let agent_key = load_account_key(&PathBuf::from(env("ONA_CROWD_AGENT_KEY_FILE")?))?;
    // A fixed seed would let anyone rebuild every key and the ground truth. This one comes from the
    // system's randomness and is never stored; `config.seed` is ignored.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sim = simulate_secret(&config, seed)?;
    let dir = PathBuf::from(dir);
    write_outputs(&sim, &config, &dir)?;

    let agent = settings.agent_account.clone();
    let mut chain =
        NearChain::connect(settings, funder_key, agent_key, &config.denominations, &config.vaults, &dir.join("tokens.txt"))?;
    // The agent account stands in for the pool and pays from its own funds. `unstake` gives nothing
    // back for several epochs, so it needs what it places and what it pays out.
    let spent: u64 = sim
        .timeline
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Placement | EventKind::ExitPayment))
        .map(|e| e.amount)
        .sum();
    let agent_transactions = sim.timeline.iter().filter(|e| e.kind != EventKind::Deposit).count() as u64;
    chain.fund(&agent, spent, agent_transactions, 0)?;
    let mut wait = |secs: u64| {
        if speed > 0 && secs > 0 {
            std::thread::sleep(Duration::from_secs(secs.div_ceil(speed)));
        }
    };
    execute(&sim, &config, &mut chain, &mut wait)?;
    println!("timeline played on {}", config.mint_account);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["simulate", config, dir] => run_offline(config, dir),
        ["run", config, dir] => run_on_near(config, dir),
        ["parades", config] => run_parades(config, "10"),
        ["parades", config, seeds] => run_parades(config, seeds),
        _ => Err(anyhow!(
            "usage: ona-crowd simulate <config.json> <out-dir> | ona-crowd run <config.json> <out-dir> | ona-crowd parades <config.json> [seeds]"
        )),
    };
    if let Err(e) = result {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
