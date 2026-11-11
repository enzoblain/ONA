# Local patch of sysinfo 0.38.4 (ONA)

Unmodified copy of `sysinfo` 0.38.4 from crates.io (MIT, see LICENSE), except one change in
`src/unix/apple/process.rs`: `open_files` returns `None` on `target_os = "ios"`, because `libc` 0.2.191 does not expose
`proc_pidinfo` / `PROC_PIDLISTFDS` / `proc_fdinfo` for iOS, so the crate does not build for `aarch64-apple-ios`.

Why it is needed: `arti-client` 0.48.0 → `tor-memquota` 0.48.0 depends on `sysinfo = 0.38.4` (feature `system`).
Applied through `[patch.crates-io]` in `../../Cargo.toml`. Remove when an upstream release builds for iOS.
Tests, benches and examples were removed (md_doc is kept: the sources include it) from the copy.
