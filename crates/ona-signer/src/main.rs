//! `ona-signer init-keys <file> <count>` creates the mint keys and prints their public halves.
//! `ona-signer run` issues tokens, configured by the environment variables in `docs/INSTALL.md`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ona_near::{check_chain_id, check_network, load_account_key, Client};
use ona_signer::crossrpc::{check_rpc_pair, CrossRpc, HttpRpc, Rpc};
use ona_signer::near::NearChain;
use ona_signer::{refuse_new_state_with_locked_deposits, state_binding, FileDurable, KeyStore, Signer};

const TICK: Duration = Duration::from_secs(5);
/// Shorter than the generic client's: a pass must not stall on one slow call.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn init_keys(path: &Path, count: usize) -> Result<(), String> {
    if count == 0 || count > 8 {
        return Err("count must be between 1 and 8".into());
    }
    let keys = KeyStore::generate(count);
    keys.save(path)?;
    for (id, pk) in keys.public_keys().iter().enumerate() {
        println!("denom {id}: {}", hex(pk));
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let rpc = env("ONA_RPC_URL")?;
    let rpc_2 = env("ONA_RPC_URL_2")?;
    check_rpc_pair(&rpc, &rpc_2)?;
    let chain_id = env("ONA_CHAIN_ID")?;
    let mint = env("ONA_MINT")?;
    let account = env("ONA_SIGNER_ACCOUNT")?;
    let account_key =
        load_account_key(&PathBuf::from(env("ONA_SIGNER_ACCOUNT_KEY_FILE")?)).map_err(|e| e.to_string())?;
    let keys = KeyStore::load(&PathBuf::from(env("ONA_SIGNER_KEYS_FILE")?))?;
    let state = FileDurable::open(&PathBuf::from(env("ONA_SIGNER_STATE_FILE")?), &state_binding(&mint, &keys))?;
    let is_new = state.is_new();

    let reads = CrossRpc::new(HttpRpc::new(&rpc, RPC_TIMEOUT)?, HttpRpc::new(&rpc_2, RPC_TIMEOUT)?);
    let client = Client::connect(&rpc, account_key).map_err(|e| e.to_string())?;
    // Both endpoints must serve the expected chain, never mainnet.
    check_network(&client, &chain_id).map_err(|e| e.to_string())?;
    let second_status = reads.second.post("status", serde_json::json!([]))?;
    check_chain_id(&chain_id, second_status["chain_id"].as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
    let mut chain = NearChain::new(client, reads, account, mint);
    let mut signer = Signer::new(keys, state);
    signer.check_keys(&mut chain)?;
    refuse_new_state_with_locked_deposits(&mut chain, is_new)?;
    println!("keys match the contract, running");
    loop {
        match signer.tick(&mut chain) {
            Ok(report) => {
                if !report.locked.is_empty()
                    || !report.issued.is_empty()
                    || !report.unlocked.is_empty()
                    || !report.skipped.is_empty()
                {
                    println!(
                        "locked {:?}, issued {:?}, unlocked {:?}, skipped {:?}",
                        report.locked, report.issued, report.unlocked, report.skipped
                    );
                }
            }
            Err(e) => eprintln!("tick failed: {e}"),
        }
        // Restarting reopens the state file, which repairs a partial last line.
        if let Some(reason) = signer.halted() {
            return Err(format!("stopping, durable state is unsafe: {reason}"));
        }
        std::thread::sleep(TICK);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["init-keys", path, count] => match count.parse() {
            Ok(count) => init_keys(Path::new(path), count),
            Err(_) => Err("count must be a number".to_string()),
        },
        ["run"] => run(),
        _ => Err("usage: ona-signer init-keys <file> <count> | ona-signer run".to_string()),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
