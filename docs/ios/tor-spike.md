# Tor on iPhone: spike (step 1)

Created on 2026-11-10.

> **Update:** the test app `ios/TorSpike` and its script `test-onion/run.sh` were removed (branch `ios-unified-app`).
> Arti is now in the ONA app (Tor tab). They remain in the git history (commit `2ef5dfe`). For a test `.onion`:
> `ios/MockComputer/run_onion.sh`. The measurements below were made with the earlier test app.

## What existed

| Path | Role |
|---|---|
| `ios/ArtiBridge/` | Rust crate `arti-bridge`: C interface around `arti-client` 0.48.0, compiled as a static library (`ArtiBridge.xcframework`, iPhone + Apple silicon simulator). |
| `ios/ArtiBridge/examples/smoke.rs` | Test of the C interface on the Mac: starts Arti, then an HTTP GET through Tor. |
| `ios/TorSpike/` | Test SwiftUI app: starts Arti, queries a `.onion`, in-memory log of measurements, export through the share sheet. |
| `ios/TorSpike/test-onion/run.sh` | Test `.onion` server on the Mac (C Tor + `python3 -m http.server`). The service key stays outside the repository. |

Bridge interface (`ios/ArtiBridge/include/ArtiBridge.h`): `bootstrap`, `status`, `http_get`, `set_dormant`,
`shutdown`, `version`. Replies are JSON; blocking calls go through a serial queue on the Swift side.

## Run (test app, now removed)

```bash
ios/ArtiBridge/build-xcframework.sh          # ~5 min the first time
cp ios/TorSpike/Config/Local.xcconfig.example ios/TorSpike/Config/Local.xcconfig   # then fill it in
ios/TorSpike/test-onion/run.sh               # prints the .onion address
open ios/TorSpike/TorSpike.xcodeproj         # TorSpike target, test iPhone
```

Test on the Mac, without an iPhone:

```bash
cd ios/ArtiBridge && cargo run --release --example smoke -- <address>.onion
```

In the app: "Cold start" erased Arti's cache before starting; without that box, an existing cache gave a warm start.
The log recorded the network (Wi-Fi / cellular), the switches between background and foreground (Arti goes dormant in
the background) and an automatic request on return. "Probe every 30 s" was for the network-change test.

## Choices made

- **Arti's permission check disabled** (`fs-mistrust`, `dangerously_trust_everyone`). The iOS sandbox already isolates
  the app, and the app does not control the permissions of the container's parent folders. Not tested with the check
  enabled.
- **Arti's cache and state in `Library/Caches/arti`**: excluded from backups, iOS may purge them. This is what allows
  a warm start. It goes against "nothing on disk except the pairing": an open question, not settled yet.
- **Local patch of `sysinfo` 0.38.4** (`ios/ArtiBridge/patches/`): the version required by `tor-memquota` 0.48.0 does
  not compile for iOS (`proc_pidinfo` missing from `libc` for iOS). The patch makes `open_files` return `None` on iOS.
  Details in `patches/sysinfo-0.38.4/ONA-PATCH.md`.
- TLS for Tor links: `native-tls` (Apple's Security.framework), no embedded copy of OpenSSL.
- Embedded SQLite (`static-sqlite`) rather than the system one.

## Findings of 2026-11-10

Mac on macOS 27.2, Xcode 27.0 beta (27A5194q), Rust 1.97.1, arti-client 0.48.0, C Tor 0.4.9.16 (Homebrew,
OpenSSL 4.1.0).

| Finding | Detail |
|---|---|
| Build | The bridge compiles for `aarch64-apple-ios` and `aarch64-apple-ios-sim` (with the `sysinfo` patch). The app compiles for the simulator and for the iPhone (Release, unsigned). |
| Simulator | The app launches on an iPhone 17 simulator; the Swift → Rust call (`version`) works. Tor startup not tried in the simulator. |
| Sizes (Mac, not a measure of "added size") | iOS release `libarti_bridge.a`: 18,519,800 bytes. Unsigned Release arm64 `TorSpike` executable, with Arti: 9,842,512 bytes. No reference build without Arti yet to compute the difference. |
| **Mac's network: Tor blocked** | C Tor stays at 10 % ("connections died … handshaking (TLS)", CONNECTRESET, NOROUTE); Arti through `smoke` fails the same way ("TLS error in TLS negotiation", timeouts). Ordinary HTTPS works. Two implementations, two different TLS stacks, same failure: the network used (Ethernet, no Wi-Fi joined) seems to filter Tor. Not yet retried on another network. |
| Signing | Xcode 27 beta has no Apple account configured: signing for the iPhone from the command line is impossible. |

### Later on 2026-11-10, on another network (Mac, not iPhone)

Tor gets through. `smoke` (Arti 0.48.0 on the Mac, empty cache): startup in 14,300 ms, then a GET to example.com
succeeded twice. To the test `.onion` (C Tor 0.4.9.16 on the same Mac): 1st request connection 7,169 ms / total
7,757 ms, 2nd request connection 446 ms / total 1,004 ms (HTTP 200, 214 bytes). A single run: to be repeated before
drawing a figure from it.

### Size (2026-11-10, Xcode 27.0 beta, Release arm64, arti-client 0.48.0)

Unsigned `TorSpike` executable: 9,843,136 bytes. Link map (`-Wl,-map`): the symbols coming from `libarti_bridge.a`
take 4,822,292 bytes, the rest of the code (the app's Swift, stubs) 247,038 bytes; the remaining ~4.8 MB (headers,
unwind tables, `__LINKEDIT`) are not attributed by the map. Size added by Arti: between 4.8 and 9.6 MB of uncompressed
executable, depending on how the rest is attributed. Download size (compressed) not measured.

### iPhone 16 (iOS 27.2, build 24B5089g)

App installed and launched on 2026-11-10 (Release, signed with a free account).

Incident on the Mac side, 15:36: the Mac's network dropped for ~112 s. Afterwards the `.onion` service (C Tor 0.4.9.16)
no longer answered, neither the iPhone (request timed out after 60 s) nor Arti on the Mac (timed out after 120 s),
while Arti still reached example.com. Restarting C Tor fixed the problem (request OK at 15:47). A single observation,
cause not established. Consequence for `ona-core`: the computer's onion service should be checked after a network
outage.

Log exported from the app, 2026-11-10 around 15:49 Paris time (the log records time in UTC), iPhone on cellular, a
single run:

| Measurement | Value |
|---|---|
| Warm start (cache present, app relaunched) | 714 ms (Rust), 716 ms seen from Swift |
| Arti cache on disk after startup | 10.8 MB |
| 1st request to the `.onion` after startup | connection 3,013 ms, total 3,317 ms |
| Request on return from ~1 s in the background | connection 350 ms, total 633 ms |
| Summary | 2 requests OK, 0 failures |

The 10.8 MB cache is the cost of the warm start, to weigh in the open question above (nothing on disk except the
pairing).

Not yet measured on the iPhone:

- cold start (no reading);
- network change Wi-Fi ↔ cellular during the 30 s probe (no reading);
- long background (2 and 10 minutes): the only switch recorded lasted ~1 s;
- repetitions: a single run so far;
- download size (compressed app).

## Possible consequence for ONA (to be checked)

If a network blocks Tor, bridges are needed (obfs4, Snowflake…). On a computer, Arti runs a pluggable transport as a
separate process; an iOS app cannot start child processes. So a transport built into the app would be needed
(libraries exist, not evaluated). To be listed in the limitations if the remote control must work on that kind of
network.
