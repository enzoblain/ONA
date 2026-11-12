#!/bin/sh
# Runs every test, then builds the three contracts the way SPEC.md describes ("Reproducing the contract hashes"),
# the pool's test build (one-minute admin delay) and the test staking pool `ona-sandbox-pool` deploys on a local node,
# and prints their SHA-256. Needs Rust 1.99.1 and its wasm32-unknown-unknown target. No key, funded account,
# Docker or browser.
set -eu
cd "$(dirname "$0")"
ROOT="$(pwd)"

# The desktop apps are built outside the workspace, each with its own Cargo.lock. Each lock must match its
# Cargo.toml (`--locked` would fail otherwise), and a package it shares with the root must have the root's version
# within the same compatible series (same major version, or same minor for 0.x). Another series, such as an
# older major version a desktop library needs, is not compared.
#
# `cache-may-lack` (the Tauri app): when some of its crates are not in the offline cache, cargo cannot check the
# lock at all. The step then says so, prints any version that differs from the root as a warning, and goes on.
check_desktop_lock() {
    dir="$1"
    update="cargo update --manifest-path $dir/Cargo.toml --workspace"
    align="cargo update --manifest-path $dir/Cargo.toml -p <name>@<listed version> --precise <root version>"
    differing="$(awk 'function series(v,   p) {
            gsub(/"/, "", v); split(v, p, /[.+-]/)
            if (p[1] != "0") return p[1]
            if (p[2] != "0") return "0." p[2]
            return "0.0." p[3]
        }
        FNR == 1 { file++; name = "" }
        /^\[\[package\]\]/ { name = "" }
        /^name = / { name = $3 }
        /^version = / && name != "" {
            key = name " " series($3)
            if (file == 1) root[key] = $3
            else if ((key in root) && root[key] != $3) print "  " name " " $3 " (root has " root[key] ")"
        }' Cargo.lock "$dir/Cargo.lock")"
    if errors="$(cargo metadata --offline --locked --format-version 1 --manifest-path "$dir/Cargo.toml" 2>&1 >/dev/null)"; then
        if [ -n "$differing" ]; then
            echo "$dir/Cargo.lock has versions that differ from the root Cargo.lock:" >&2
            echo "$differing" >&2
            echo "Align each one with: $align" >&2
            exit 1
        fi
        echo "$dir/Cargo.lock is up to date"
    elif printf '%s\n' "$errors" | grep -q -e "locked was passed" -e "needs to be updated"; then
        echo "$dir/Cargo.lock does not match its Cargo.toml. Update it with: $update" >&2
        exit 1
    elif [ "${2:-}" = "cache-may-lack" ] && printf '%s\n' "$errors" | grep -q -e "no matching package" -e "failed to download" -e "HTTP request"; then
        echo "warning: $dir/Cargo.lock not checked: some of its crates are not in the offline cache"
        if [ -n "$differing" ]; then
            echo "warning: versions that differ from the root Cargo.lock:"
            echo "$differing"
            echo "warning: align them online with: $align"
        fi
    else
        printf '%s\n' "$errors" >&2
        exit 1
    fi
}
check_desktop_lock desktop/OnaCoreBridge
check_desktop_lock desktop/tauri/src-tauri cache-may-lack

cargo test --locked --workspace
# The pool's test build: its own unit tests, which check the shortest admin delay it accepts.
cargo test --locked -p ona-pool --lib --features short-admin-delay

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

OUT=target/wasm32-unknown-unknown/contract
# The pool's test build (`short-admin-delay`: an admin delay of one minute is allowed), for a local node and testnet
# only. Built first and copied, because the normal build below writes the same file.
cargo build --locked --profile contract --target wasm32-unknown-unknown -p ona-pool --features short-admin-delay \
    --config crates/ona-pool/wasm-build.toml --config "$REMAP"
cp "$OUT/ona_pool.wasm" "$OUT/ona_pool_short_admin_delay.wasm"

for crate in ona-mint ona-registry ona-pool ona-test-staking; do
    cargo build --locked --profile contract --target wasm32-unknown-unknown -p "$crate" \
        --config "crates/$crate/wasm-build.toml" --config "$REMAP"
done
if cmp -s "$OUT/ona_pool.wasm" "$OUT/ona_pool_short_admin_delay.wasm"; then
    echo "the pool's test build is the same as its normal build: the short-admin-delay feature did not apply" >&2
    exit 1
fi

# Fails if a wasm still names a local directory or the user's home directory, found by its full path.
HOME_DIR="$(cd ~ 2>/dev/null && pwd || true)"
for name in ona_mint ona_registry ona_pool ona_test_staking ona_pool_short_admin_delay; do
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
echo "All tests passed and the three contracts, the pool's test build and the test staking pool compile to wasm without local paths."
