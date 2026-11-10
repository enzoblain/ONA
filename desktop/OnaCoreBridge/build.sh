#!/bin/sh
# Builds OnaCore.xcframework (macOS, Apple silicon) from the Rust bridge around ona-core.
set -eu
cd "$(dirname "$0")"
if [ -z "${DEVELOPER_DIR:-}" ] && ! xcode-select -p | grep -q '\.app/'; then
    export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
fi
export MACOSX_DEPLOYMENT_TARGET=26.0
# --crate-type staticlib: only the static library, so that LTO applies.
cargo rustc --locked --release --lib --crate-type staticlib  # host build: Apple-silicon Mac
rm -rf OnaCore.xcframework
xcodebuild -create-xcframework \
    -library target/release/libona_core_bridge.a -headers include \
    -output OnaCore.xcframework
