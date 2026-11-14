# ONA documents

Start with the [README](../README.md).

## State and design

- [STATUS.md](STATUS.md): what works today, per component, and what each part was tested on.
- [DESIGN.md](DESIGN.md): the problem, what pseudonyms cover, the architecture, how paying works, next steps, known limitations.
- [SPEC.md](../SPEC.md): the build spec (contracts, tokens, measured gas).

## Run and build

- [INSTALL.md](INSTALL.md): install, run the core, verify the contracts, local NEAR node runs, deployment.
- [TOR.md](TOR.md): Tor for the client, the relay and the desktop apps; [torrc.client.example](torrc.client.example), [torrc.relay.example](torrc.relay.example).
- [RELEASE.md](RELEASE.md): how the apps are built and published (GitHub Actions, signing, TestFlight).
- [try/research.jsonl](try/research.jsonl): the commands of a free research on the demo web, for `ona < docs/try/research.jsonl`.

## Features

- [research.md](research.md): free research with sources, and actions the person completes.
- [desktop/pool-commands.md](desktop/pool-commands.md): the pool commands of `ona-core`.
- [desktop/privacy.md](desktop/privacy.md): the pool's privacy figures (`pool_privacy`).
- [desktop/wallet.md](desktop/wallet.md): pool deposits from the person's own NEAR wallet.

## Apps

- [desktop/app.md](desktop/app.md): the macOS app.
- [desktop/tauri.md](desktop/tauri.md): the Windows and Linux app.
- [ios/app.md](ios/app.md): the iPhone app.
- [ios/protocol-draft.md](ios/protocol-draft.md): the phone ↔ computer protocol, version 1.
- [ios/tor-spike.md](ios/tor-spike.md): Tor on iPhone, first measurements.
