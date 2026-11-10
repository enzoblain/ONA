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

`NEAR_SANDBOX_BIN_PATH` is the only environment variable the code reads, through the `near-sandbox` crate. **This harness has not
completed a run yet**, so expect to fix things. The node crashes when started inside a macOS Seatbelt sandbox, so run it from a
normal terminal.

## Not available yet

No NEAR testnet deployment, real model connection, Tor, enclave, desktop app or iOS app. See the status table in the [README](../README.md).
