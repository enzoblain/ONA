#!/bin/sh
# Runs every test. Needs Rust and the wasm32-unknown-unknown target. No key, funded account, Docker or browser.
set -eu
cd "$(dirname "$0")"
cargo test --workspace
cargo build --profile contract --target wasm32-unknown-unknown -p ona-mint --config crates/ona-mint/wasm-build.toml
cargo build --profile contract --target wasm32-unknown-unknown -p ona-registry --config crates/ona-mint/wasm-build.toml
echo "All tests passed and both contracts compile to wasm."
