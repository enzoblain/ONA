//! `ona-signer init-keys <file> <count>` creates the mint keys and prints their public halves.
//! `ona-signer run` issues tokens, configured by the environment variables in `docs/INSTALL.md`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ona_near::{load_account_key, Client};
use ona_signer::near::NearChain;
use ona_signer::{FileDurable, KeyStore, Signer};

const TICK: Duration = Duration::from_secs(5);

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
    let mint = env("ONA_MINT")?;
    let account = env("ONA_SIGNER_ACCOUNT")?;
    let account_key =
        load_account_key(&PathBuf::from(env("ONA_SIGNER_ACCOUNT_KEY_FILE")?)).map_err(|e| e.to_string())?;
    let keys = KeyStore::load(&PathBuf::from(env("ONA_SIGNER_KEYS_FILE")?))?;
    let state = FileDurable::open(&PathBuf::from(env("ONA_SIGNER_STATE_FILE")?))?;

    let mut chain = NearChain::new(Client::new(&rpc, account_key), account, mint);
    let mut signer = Signer::new(keys, state);
    signer.check_keys(&mut chain)?;
    println!("keys match the contract, running");
    loop {
        match signer.tick(&mut chain) {
            Ok(report) => {
                if !report.locked.is_empty() || !report.issued.is_empty() || !report.skipped.is_empty() {
                    println!("locked {:?}, issued {:?}, skipped {:?}", report.locked, report.issued, report.skipped);
                }
            }
            Err(e) => eprintln!("tick failed: {e}"),
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
