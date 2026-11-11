#!/bin/sh
# Builds ArtiBridge.xcframework (device + Apple-silicon simulator) from the Rust crate.
# Needs: rustup targets aarch64-apple-ios and aarch64-apple-ios-sim, and Xcode (DEVELOPER_DIR is set to the beta
# below if xcode-select still points to the Command Line Tools).
set -eu
cd "$(dirname "$0")"

if [ -z "${DEVELOPER_DIR:-}" ] && ! xcode-select -p | grep -q '\.app/'; then
    export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
fi
export IPHONEOS_DEPLOYMENT_TARGET=17.0

# --locked: build exactly the versions in Cargo.lock.
# --crate-type staticlib: only the static library, so that LTO applies (Cargo.toml also declares "lib" for examples/).
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    cargo rustc --locked --release --lib --crate-type staticlib --target "$target"
done

rm -rf ArtiBridge.xcframework
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libarti_bridge.a -headers include \
    -library target/aarch64-apple-ios-sim/release/libarti_bridge.a -headers include \
    -output ArtiBridge.xcframework

ls -l target/aarch64-apple-ios/release/libarti_bridge.a
