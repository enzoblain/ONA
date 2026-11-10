# Install and run

Tested only on macOS on Apple Silicon, with Rust 1.99.1. Other platforms are untested.

## Prerequisites

```
rustup target add wasm32-unknown-unknown
```

A C compiler is also needed, for `blst`. On macOS: `xcode-select --install`.

## Check everything

```
./verify.sh
```

This runs all tests and compiles both contracts to wasm. It needs no key, no funded account, no Docker and no browser.

To type-check only, use `cargo check --workspace --all-targets`. Plain `cargo check` fails on purpose: `near-sdk` refuses to build
a contract for a native target outside tests.

## Try it

A full mission against a fake model, a fake web and fake payments:

```
cargo run -p ona-core --bin ona -- demo
```

Without `demo`, `ona` reads one JSON request per line on stdin and prints one JSON reply per line. Every reply says `"mode":"mock"`.

A fake relay on localhost, for front-end work:

```
cargo run -p ona-server --bin ona-mock-relay -- 8787
```

Its startup output gives the request key and domain tag. Routes, all `POST` with a JSON body:

| Route | Body | Reply |
|---|---|---|
| `/dev/credit` | `{}` | a free test credit: `token`, `owner_sig`. Exists only in this binary |
| `/exchange` | `token`, `owner_sig`, `blinded` (8 hex points) | 202 while pending, then 200 with `signatures` when the same request is repeated |
| `/chat` | `token` (hex, 80 bytes), `prompt` | `reply`, `tokens_used`, `mode` |

## Measure gas on a local node

```
cargo build --profile contract --target wasm32-unknown-unknown -p ona-mint --config crates/ona-mint/wasm-build.toml
NEAR_SANDBOX_BIN_PATH=/path/to/near-sandbox cargo run -p ona-sandbox
```

`NEAR_SANDBOX_BIN_PATH` is read by the `near-sandbox` crate. This deploys the contract
on a local node, calls every method, prints the gas burnt, then runs the real signer loop and a real relay exchange against the node.
The node crashes when started inside a macOS Seatbelt sandbox, so run it from a normal terminal.

## Deploy the contracts

Testnet or a local node only: the tool refuses mainnet. Build both contracts as in `verify.sh`, and create the signer keys as below. Each
contract becomes `mint.<parent>` or `registry.<parent>`, created and initialized in one transaction, with no access key.

| Variable | Value |
|---|---|
| `ONA_RPC_URL`, `ONA_NETWORK` | NEAR RPC endpoint and network name |
| `ONA_PARENT_ACCOUNT`, `ONA_PARENT_KEY_FILE` | funded parent account, and its key in a file readable by its owner only |
| `ONA_SIGNER_KEYS_FILE` | mint only: the file from `ona-signer init-keys` |
| `ONA_SIGNER_ACCOUNT`, `ONA_RELAY_ACCOUNT`, `ONA_GUARDIAN_ACCOUNT` | mint only: the three roles |
| `ONA_REGISTRY_OWNER_1`, `ONA_REGISTRY_OWNER_2`, `ONA_AGGREGATOR_ACCOUNT` | registry only |
| `ONA_FUNDING_NEAR` | optional, NEAR sent to the new account, default 5 |
| `ONA_BASE_VALUE_MILLI_NEAR` | optional, mint only, value of the lowest tier, default 100 |
| `ONA_CIRCULATION_CAP`, `ONA_HOURLY_REDEEM_CAP` | optional, mint only, per tier, default 1000 and 100 |
| `ONA_MINT_WASM`, `ONA_REGISTRY_WASM` | optional, paths to the built contracts |

```
cargo run -p ona-deploy -- mint
cargo run -p ona-deploy -- registry
```

## Run the signer

```
cargo run -p ona-signer -- init-keys signer-keys.bin 8
```

This creates the mint keys in a new private file, and prints the public keys to give to the contract at deployment. Each deployment
needs its own keys. To issue tokens:

| Variable | Value |
|---|---|
| `ONA_RPC_URL` | NEAR RPC endpoint |
| `ONA_MINT` | account of the deployed contract |
| `ONA_SIGNER_ACCOUNT` | account named as signer in the contract |
| `ONA_SIGNER_ACCOUNT_KEY_FILE` | file holding `ed25519:<base58>`, readable by its owner only |
| `ONA_SIGNER_KEYS_FILE` | the file from `init-keys` |
| `ONA_SIGNER_STATE_FILE` | where the signer records its progress; must survive restarts |

```
cargo run -p ona-signer -- run
```

It refuses to start if its keys are not the ones the contract verifies against.

## Run the relay

```
cargo run -p ona-server --bin ona-relay -- init-key relay-request-keys.bin
```

To serve, on `127.0.0.1` only:

| Variable | Value |
|---|---|
| `ONA_RPC_URL` | NEAR RPC endpoint |
| `ONA_MINT` | account of the deployed contract |
| `ONA_NETWORK` | network name used when the contract was created |
| `ONA_RELAY_ACCOUNT` | account named as relay in the contract |
| `ONA_RELAY_ACCOUNT_KEY_FILE` | file holding `ed25519:<base58>`, readable by its owner only |
| `ONA_RELAY_REQUEST_KEY_FILE` | the file from `init-key` |
| `ONA_RELAY_STORE_FILE` | where the relay records exchanges; must survive restarts |
| `ONA_MODELS` | allowed models, separated by commas |
| `NEAR_AI_CLOUD_API_KEY` | NEAR AI key. Set it with `read -s`, never in a file |
| `ONA_RELAY_PORT` | optional, default 8787 |
| `ONA_FLUSH_SECS` | optional, seconds between batches of claims, default 60 |
| `ONA_TOKENS_PER_CREDIT` | optional, default 100 |
| `ONA_MAX_TOKENS` | optional, most tokens per reply, default 512 |

```
cargo run -p ona-server --bin ona-relay -- run
```

## Not available yet

No NEAR testnet deployment, real model connection, Tor, enclave, desktop app or iOS app. See the status table in the [README](../README.md).
