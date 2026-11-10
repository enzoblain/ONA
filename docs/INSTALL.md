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
