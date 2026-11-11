#!/bin/sh
# Runs every test, then builds the three contracts the way SPEC.md describes ("Reproducing the contract hashes")
# and prints their SHA-256. Needs Rust 1.99.1 and its wasm32-unknown-unknown target. No key, funded account,
# Docker or browser.
set -eu
cd "$(dirname "$0")"
ROOT="$(pwd)"

cargo test --locked --workspace

# A contract keeps the source path of every panic location. Each machine-specific prefix is rewritten, so the
# wasm, and the code hash the chain records, do not depend on who built it or where.
# Flags from the environment would replace those of the build configuration, rewrites included.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
CARGO_DIR="${CARGO_HOME:-${HOME:-/nonexistent}/.cargo}"
SYSROOT="$(rustc --print sysroot)"
COMMIT="$(rustc -vV | sed -n 's/^commit-hash: //p')"
for dir in "$CARGO_DIR" "$SYSROOT" "$ROOT"; do
    case "$dir" in
        *'"'* | *'\'* | *'='*) echo "cannot build reproducibly from a path containing a quote, a backslash or '=': $dir" >&2; exit 1 ;;
    esac
done
REMAP="build.rustflags=[\"--remap-path-prefix=$CARGO_DIR=/cargo\",\"--remap-path-prefix=$SYSROOT/lib/rustlib/src/rust=/rustc/$COMMIT\",\"--remap-path-prefix=$ROOT=/ona\"]"

for crate in ona-mint ona-registry ona-pool; do
    cargo build --locked --profile contract --target wasm32-unknown-unknown -p "$crate" \
        --config "crates/$crate/wasm-build.toml" --config "$REMAP"
done

# Fails if a wasm still names a local directory or the user's home directory, found by its full path.
HOME_DIR="$(cd ~ 2>/dev/null && pwd || true)"
for name in ona_mint ona_registry ona_pool; do
    wasm="target/wasm32-unknown-unknown/contract/$name.wasm"
    for pattern in "$ROOT" "$CARGO_DIR" "$SYSROOT" "${HOME:-}" "$HOME_DIR" "/Users/" "/home/"; do
        if [ -n "$pattern" ] && [ "$pattern" != "/" ] && LC_ALL=C grep -a -F -q -e "$pattern" "$wasm"; then
            echo "$wasm contains a local path ($pattern)" >&2
            exit 1
        fi
    done
    if command -v sha256sum >/dev/null 2>&1; then
        sum="$(sha256sum "$wasm" | cut -d ' ' -f 1)"
    else
        sum="$(shasum -a 256 "$wasm" | cut -d ' ' -f 1)"
    fi
    echo "$name.wasm sha256 $sum"
done
echo "All tests passed and the three contracts compile to wasm without local paths."
