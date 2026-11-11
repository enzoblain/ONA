<img src="assets/logo.png" alt="ONA logo" width="120">

# ONA: a private AI assistant, built so that no one links who you are to what you ask

Built at NEAR HACKATHON · Tracks: to be confirmed · Network: NEAR testnet (planned) · Not audited

> **Status: early prototype, not audited.** The token crypto, the two contracts, the signer and relay logic, the wallet and the
> local mission core exist and pass their tests. The mint contract has run on a local NEAR node, with measured gas. The model and the
> web are still fake, and nothing is deployed on testnet. **Do not use real funds.** See [what works today](#what-works-today).

## What it is

ONA is an AI assistant for sensitive matters: legal, medical, financial or professional questions you would not want
tied to your name. You talk to it from your computer or your phone. It can also act on your behalf (search the web,
contact a professional, make a payment), and asks for your explicit confirmation before each of these actions.

The difference is who sees what. ONA is designed so that no single party gets both who you are and what you asked:

- **the model** reads your request with names replaced by pseudonyms, inside an enclave (NEAR AI Cloud);
- **websites and the people the agent contacts** see Tor traffic and a generic message, not you;
- **payments** use blind tokens: the mint that holds your deposit cannot link it to what you pay for;
- **your phone** talks to your own computer over Tor, and the agent runs on that computer, not on our servers.

After each mission, ONA shows an **exposure report**: every party that received something, and exactly what it received.

This is the design. Today the model, the web and the payments in the app are still fakes; see
[what works today](#what-works-today) and the [known limitations](#known-limitations).

Example: find a labour lawyer and compare fees on a generic version of your case, without the firms you did not pick
learning who you are.

## The problem

A hosted AI chat links your identity, your conversations and your actions at one operator. Encrypted inference helps
with the content, but the account, the network address, the payment and the agent's actions still identify you.

## Planned architecture

| Component | Role | Language |
|---|---|---|
| `ona-core` | Runs on the user's computer: mission state machine, payment gate, pseudonyms, E2EE client for NEAR AI Cloud, wallet tokens, sealed state, journal, exposure report. Reaches the network through a local `tor` over SOCKS5 (`ona-tor`) | Rust |
| Desktop app | Connects a NEAR wallet for deposits, starts missions, asks for confirmations, shows the exposure report | Swift (SwiftUI) on macOS; Rust + Tauri with HTML/JavaScript on Windows and Linux; both on `ona-core` (to be confirmed) |
| iOS app | Remote control of the computer over Tor: mission progress and confirmations. Holds no tokens and no pseudonym table | Swift |
| `ona-server` | Thin relay in a TEE (Phala dstack): holds the NEAR AI Cloud key, enforces a flat request size, submits transactions | Rust |
| `ona-signer` | Blind-signs tokens after on-chain deposits; no inbound network | Rust |
| `ona-mint` | NEAR contract: holds the reserve, verifies blind BLS12-381 tokens, pays recipients directly, returns blinded change | Rust |
| `ona-registry` | NEAR contract: published measurements, journal anchors, incident level | Rust |

## How paying works (planned)

1. **Top up.** Connect a NEAR wallet and confirm one deposit to `ona-mint`. This is the only time the wallet signs.
2. **Send a mission.** The app shows the plan and the price. You confirm. Blind tokens are spent locally, with no transaction.
3. **Pay a third party.** You confirm the recipient and the amount. `ona-mint` pays directly and returns blinded change.

## What works today

| Part | State | Tested on |
|---|---|---|
| `ona-token` blind BLS tokens | done | native tests |
| `ona-mint` contract | done, gas measured ([SPEC](SPEC.md#measured-gas)) | mocked NEAR VM with real BLS and ed25519 host functions, and a local NEAR node |
| `ona-registry` contract | done | mocked NEAR VM only |
| `ona-anchor` hourly journal anchoring, auditor key sealing in `ona-core` | library done, no program receives leaves yet | fake registry only, never on a NEAR node |
| `ona-deploy` deployment tool | done, refuses mainnet, testnet not tried yet | unit tests |
| `ona-near` RPC client | done | unit tests, and a local NEAR node through `ona-sandbox` |
| `ona-signer` issuing loop | done, keys in a local file | fake chain, and a local NEAR node |
| `ona-server` relay | logic, HTTP, chain client and encrypted NEAR AI gateway done; the `ona-relay` program has not run yet | fake chain and fake NEAR AI, and a local NEAR node for the chain path |
| `ona-wallet` encrypted wallet file | done, keychain not wired in | native tests |
| `ona-core` mission, gate, sealed journal, 24-hour chat deletion | done | fake model, web and payments, each labelled `mode: mock` |
| `ona-core` encrypted NEAR AI client | done, quote verification missing, not yet connected to missions | simulated enclave. The same protocol passed one real call from a test script |
| Desktop app (`desktop/`, macOS) | conversations and confirmations driven by `ona-core` (fake model, web and payments), phone pairing and the phone protocol; no wallet yet | Mac tests with the real `ona-core`, one end-to-end run with the iOS simulator on the local network ([notes](docs/desktop/app.md)) |
| Desktop app (`desktop/tauri`, Windows and Linux) | same features and protocol as the macOS app, in Rust with Tauri; no wallet yet | Rust tests with the real `ona-core`, one end-to-end run with the iOS simulator on the local network, run on macOS. Never built or run on Windows or Linux ([notes](docs/desktop/tauri.md)) |
| iOS app (`ios/`) | Tor (Arti embedded): an earlier test build reached a test onion service; the Tor screen is now a tab of the app | one iPhone 16, one series of measurements ([notes](docs/ios/tor-spike.md)) |
| iOS app (`ios/`) | chat-style conversations with the agent, QR pairing and signed messages and confirmations against a mock computer, labelled `mode: mock` (the mock replays one demo mission for any request). Over Tor (Arti), pairing, polling and a signed confirmation passed once end to end in the simulator. The Secure Enclave key path has not run on a device yet | iOS simulator (software key), unit tests on the Mac ([notes](docs/ios/app.md)) |
| `ona-tor` client through Tor | library done, no program uses it yet ([docs/TOR.md](docs/TOR.md)) | fake SOCKS server only, never on the real Tor network |
| Phala enclave | not built | none |

## Run it

Setup and details are in [docs/INSTALL.md](docs/INSTALL.md). To contribute, see [CONTRIBUTING.md](CONTRIBUTING.md).

`./verify.sh` runs every test and compiles the contracts. It needs Rust and the `wasm32-unknown-unknown` target, and no key,
no funded account, no Docker and no browser.

```
cargo run -p ona-core --bin ona -- demo     # a full mission against the fakes
cargo run -p ona-server --bin ona-mock-relay -- 8787     # a fake relay on localhost for front-end work
```

To measure gas on a local node, build the contract as in `verify.sh`, set `NEAR_SANDBOX_BIN_PATH` to a `near-sandbox` binary, and run
`cargo run -p ona-sandbox`.

## Known limitations

- At launch the anonymity set is one, so ONA claims no unlinkability until a measured number of users is published.
- Deposits are public on chain and show that an account uses ONA.
- The model enclave reads the pseudonymized prompt by design, under a TEE assumption.
- NEAR AI Cloud keeps one usage row per request.
- The computer must be on for a mission to progress.
- The same team would operate the relay, the signer and the anchoring.
- Testnet only. The mint has no real-money deployment planned.
- **A dishonest relay may still be able to read replies.** With encryption version 2, the relay controls which client key the reply is encrypted to.
  The client now uses version 3, which binds the reply key, but this fixes the problem only if the NEAR AI gateway accepts version 3, which is **not verified**.
  Version 3 was tested only against a simulated enclave. A relay running in an attested enclave is not in place yet.
- The relay serves a fixed pool of connections with per-request deadlines, but a few dozen slow clients can still keep it busy. Do not expose it
  to the internet yet.
- A stolen signer key can drain the reserve at the speed of the hourly redemption limit. There is no key rotation.
- An attacker holding tokens can use up a tier's hourly limit and delay exits for that tier.

More in [SPEC.md](SPEC.md).

## Libraries and AI-generated code

Main libraries: `blst`, `near-sdk`, `near-sandbox`, `ed25519-dalek`, `sha2`, `chacha20poly1305`, `hkdf`, `serde_json`, `tokio`.

The code and tests in this repository were written with Claude (Anthropic), under human direction.

iOS side, pinned exactly (`Cargo.lock` pins the transitive ones):

| Library | Version | Used by | Notes |
|---|---|---|---|
| `arti-client` (Tor Project) | 0.48.0 | `ios/ArtiBridge` (the iOS app) | Features: tokio, native-tls, compression, onion-service-client, static-sqlite |
| `tor-rtcompat` (Tor Project) | 0.48.0 | `ios/ArtiBridge` | |
| `tokio` | 1.54.1 | `ios/ArtiBridge` | |
| `serde_json` | 1.0.154 | `ios/ArtiBridge` | |
| `tracing-subscriber` | 0.3.23 | `ios/ArtiBridge` | |
| `sysinfo` | 0.38.4, patched | `ios/ArtiBridge` (via `tor-memquota`) | Local copy with a one-function change so it builds for iOS: `ios/ArtiBridge/patches/sysinfo-0.38.4/ONA-PATCH.md` |

Desktop app for Windows and Linux (`desktop/tauri/src-tauri`), pinned exactly (`Cargo.lock` pins the transitive ones):

| Library | Version | Used for |
|---|---|---|
| `tauri` | 2.12.5 | window, web view, commands |
| `tauri-build` | 2.7.4 | build script |
| `p256` (RustCrypto) | 0.13.2 | checking the phone's ECDSA P-256 signatures, the computer's key |
| `sha2` | 0.10.9 | the 6-digit pairing code |
| `base64` | 0.22.1 | protocol encoding |
| `rand` | 0.8.8 | pairing codes and ids |
| `qrcode` | 0.14.1 | pairing QR code (SVG) |
| `serde`, `serde_json` | 1.0.229, 1.0.154 | JSON |

Test tooling, not shipped: C Tor 0.4.9.16 (Homebrew) runs the test onion service on the developer's Mac.
The iOS app (`ios/ONA`) uses only Apple frameworks (SwiftUI, Foundation, CryptoKit, Security, VisionKit). The mock
computer (`ios/MockComputer`) uses only the Python standard library; its P-256 code (`p256.py`) is written for the mock
only and is not meant for real keys.

## Related project

To be named.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Hugo Thomas & Enzo Blain.
