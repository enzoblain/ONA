<img src="assets/logo.png" alt="ONA logo" width="120">

# ONA: a private AI assistant that no single party can link to you

Built at NEAR HACKATHON (1 to 14 November 2026) · Track: Privacy & Private AI · Network: NEAR testnet (contracts not
deployed yet) · MIT · **Prototype, not audited. Do not use real funds.**

## The problem

People ask AI assistants about things they would not want tied to their name: a lawyer, a diagnosis, debts, a
dispute at work. Today the provider of the assistant sees both who asks and what is asked, and so does every service
the assistant acts on (search engines, websites, payment providers). A privacy policy is a promise, not a property.

## What ONA does

ONA is an assistant that runs on the person's own computer and is driven from that computer or from a phone. It is built
so that no single party receives both who the person is and what they asked:

- **The model** gets the request with declared names replaced by pseudonyms, through an end-to-end encrypted channel to
  NEAR AI Cloud (enclave inference). The relay in front of it holds the API key; the person never needs one.
- **The web** sees Tor traffic. Search queries are shown to the person and confirmed before they leave; pages are read
  through Tor; the answer cites its sources, and every quote is checked against the page it came from.
- **Actions** (a message, a payment) are only suggested: the person types the recipient, sees the exact action and
  confirms it. A message opens in the person's own mail program.
- **Payments and savings** go through NEAR contracts with blind tokens: the mint that takes a deposit cannot link it to
  what is paid, and the pool's notes do not say which vault the person chose.
- **The phone** talks to the person's own computer over Tor (an onion service published for that phone only), with
  every reply signed and every confirmation signed by a key in the phone's secure chip.
- After each conversation, an **exposure report** lists every party that received something, with request and byte
  counts (never the content).

## What NEAR does in it

| NEAR piece | Role in ONA | State |
|---|---|---|
| NEAR AI Cloud | the model, reached with end-to-end encryption (version 3) through a relay | one real encrypted call passed on 12/11/2026 (`e2ee_check`); missions run on the fake model until the relay is published |
| `ona-mint` contract | issues blind tokens for a deposit, pays them out unlinkably | built, tested on a mocked NEAR VM and a local NEAR node with measured gas; not on testnet |
| `ona-pool` contract and `ona-agent` | a shared pool of staking vaults held as blind cash and share notes | built, run end to end on a local NEAR node (deposit, cash, entry, placement, leave, payment); not on testnet |
| NEAR wallets (NEP-413, Wallet Selector) | the person deposits and signs from their own wallet; ONA never holds its keys | built in both desktop apps; not used with a real wallet yet |
| `ona-registry` contract | registry of journal checkpoints (anchoring) | built, mocked VM only |

## Try it

Each step: what to run, and what you should see. Requirements: Rust 1.99.1 ([docs/INSTALL.md](docs/INSTALL.md); tested on macOS, Apple silicon); `tor` only for the Tor parts.

1. **A full mission on the fakes, with its exposure report.**
   `cargo run -p ona-core --bin ona -- demo`
   → JSON lines for each step (plan, two pages read, the offer chosen, a message, a payment confirmed by its digest),
   ending with an exposure report: `"outputs":{"contact":1,"fetch":2,"search":1}`, `"mode":"mock"`.
2. **A free research with sources, on the demo web.**
   `cargo run -p ona-core --bin ona < docs/try/research.jsonl`
   → the proposed query, then the answer (`research_result`) with notes such as « Le déplacement coûte souvent entre 40
   et 80 euros. », each with its source `s1`/`s2` and a quote found word for word in that page; then the exposure
   report (`"outputs":{"fetch":2,"search":1}`).
3. **Every test, and the contracts built reproducibly.**
   `./verify.sh` (after `cargo fetch` once; needs the `wasm32-unknown-unknown` target)
   → all workspace tests pass and the SHA-256 of each contract is printed.
4. **The pool on a local NEAR node.** With a `near-sandbox` 2.13.4 binary you checked:
   `NEAR_SANDBOX_BIN_PATH=/path/to/near-sandbox cargo run -p ona-sandbox --bin ona-sandbox-pool`
   → deployment, a deposit and its cash issue, an entry, the placement, a leave and a payment, each step named as it
   passes, then the escape exits without the agent and the gas of every transaction. Last run on 13/11/2026: every step
   passed, 34 checks ([SPEC](SPEC.md#ona-pool-cratesona-pool)). Add `-- --serve` to keep the node running for a
   desktop app.
5. **The apps.**
   - macOS (Apple silicon): `desktop/OnaCoreBridge/build.sh`, then open `desktop/ONADesktop/ONADesktop.xcodeproj` and
     run. Or download the signed and notarized build from the
     [latest release](https://github.com/enzoblain/ONA/releases/latest).
   - Windows and Linux: `cd desktop/tauri/src-tauri && cargo tauri dev`, or the installers of the latest release.
   - iPhone: `ios/ArtiBridge/build-xcframework.sh`, then open `ios/ONA/ONA.xcodeproj` and run in the simulator; a
     TestFlight build exists, not yet open to the public.
   → Write a question: the app proposes search queries to confirm, reads the pages, answers with sources; the Pool
   window shows the portfolio and its privacy figure. In the apps, the model and the web are the demo ones (shown as a
   simulation, `mode: mock`) until `model.json` names a relay (docs/desktop/tauri.md, "Real model").

## What works today, and what does not

Real and tested:

- blind BLS tokens (`ona-token`), the mint, pool and registry contracts, the signer and relay logic, the pool agent;
- the mission core: plan, gate, pseudonyms, sealed journal, exposure report, free research with checked quotes, actions
  confirmed by digest;
- the three apps (macOS, Windows/Linux with Tauri, iPhone) and their signed phone protocol; the phone reached the
  computer's onion service through Tor (Arti) on 11/11/2026;
- builds of the four apps on GitHub's machines for every change, and a signed, notarized macOS release;
- conversations kept in memory only by the three apps, gone when the app quits: nothing about them is written to disk
  (in the Tauri app, a test checks that a conversation's text is in no file of the app's folder).

Simulated or not done (everything simulated says `mode: mock`):

- **the model**: fake in the apps unless `model.json` names a relay; one mission and one research ran with the real model
  through Tor and the team's test relay on 13/11/2026 ([docs/INSTALL.md](docs/INSTALL.md), [docs/research.md](docs/research.md));
- **the web through Tor**: one research ran end to end through Tor with the real model on 13/11/2026 (Brave Search, 4
  pages chosen, 1 read, about 12 minutes), not yet in the apps;
- **payments**: simulated in missions and actions; the mint and the pool are not on testnet;
- **enclave quotes** are not verified by the client yet: the relay could read a request;
- **not run**: the iPhone on a real device, the Tauri app on real Windows and Linux machines, a deposit from a real
  wallet.

Per-component state, what each was tested on, and the known limitations: [docs/STATUS.md](docs/STATUS.md) and
[docs/DESIGN.md](docs/DESIGN.md).

## Repository

| Path | What | Docs |
|---|---|---|
| `crates/ona-core` | the mission core: model client, gate, journal, research, pool client | [SPEC.md](SPEC.md), [docs/research.md](docs/research.md) |
| `crates/ona-mint`, `ona-pool`, `ona-registry` | NEAR contracts | [SPEC.md](SPEC.md) |
| `crates/ona-agent`, `ona-server`, `ona-signer` | pool agent, relay, signer | [docs/INSTALL.md](docs/INSTALL.md) |
| `crates/ona-token`, `ona-wallet`, `ona-near`, `ona-tor`, `ona-anchor`, `ona-crowd`, `ona-deploy`, `ona-sandbox`, `ona-test-staking` | tokens, wallet, NEAR client, Tor client, anchoring, crowd simulator, deployment, local-node runs and their test staking pool | [SPEC.md](SPEC.md) |
| `desktop/ONADesktop`, `desktop/OnaCoreBridge` | macOS app (SwiftUI) and its bridge to the core | [docs/desktop/app.md](docs/desktop/app.md) |
| `desktop/tauri` | Windows and Linux app (Tauri) | [docs/desktop/tauri.md](docs/desktop/tauri.md) |
| `desktop/wallet-page` | the page that connects the person's NEAR wallet | [docs/desktop/wallet.md](docs/desktop/wallet.md) |
| `ios/` | iPhone app, embedded Tor (Arti), a fake computer for tests | [docs/ios/app.md](docs/ios/app.md), [protocol](docs/ios/protocol-draft.md) |
| `.github/workflows` | builds and releases | [docs/RELEASE.md](docs/RELEASE.md) |

All documents: [docs/README.md](docs/README.md).

## Built during the hackathon

The repository's history starts on 10/11/2026, inside the build window (1 to 14 November 2026): every commit is
hackathon work. The first commit imports the prototype as the team had it on that day. Team: Hugo Thomas (core,
contracts, relay, pool) and Enzo Blain (apps, phone protocol, Tor on iPhone, releases).

## Libraries and AI-generated code

Main libraries: `blst`, `near-sdk`, `near-sandbox`, `ed25519-dalek`, `sha2`, `chacha20poly1305`, `hkdf`, `serde_json`, `tokio`,
`unicode-normalization`.
The NEAR client, the deployment tool and the crowd simulator also use `ureq` (with `rustls`), `bs58`, `base64`, `anyhow`, `libc`,
`zeroize`, `rand` and `rand_chacha`. The relay and the signer use `ureq` 3.5.1 and `zeroize` 1.9.1, pinned exactly; the pool agent
(`ona-agent`) uses the same libraries, through the relay's HTTP front and two-endpoint reader. `Cargo.lock` fixes
every version, and `verify.sh` builds with `--locked`.

Client core (`crates/ona-core`), pinned exactly:

| Library | Version | Used by | Notes |
|---|---|---|---|
| `unicode-normalization` | 0.1.26 | `ona-core` (pseudonyms) | NFKD and combining marks, before protected terms are compared |

The code and tests in this repository were written with Claude (Anthropic), under human direction.

iOS side, pinned exactly (`Cargo.lock` pins the transitive ones):

| Library | Version | Used by | Notes |
|---|---|---|---|
| `arti-client` (Tor Project) | 0.48.0 | `ios/ArtiBridge` (the iOS app) | Features: tokio, native-tls, compression, onion-service-client, static-sqlite, keymgr, experimental-api (the client key of a restricted onion service) |
| `tor-hscrypto`, `tor-llcrypto` (Tor Project) | 0.48.0 | `ios/ArtiBridge` | the onion address and the x25519 client key given to Arti |
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
| `p256` (RustCrypto) | 0.13.2 | checking the phone's ECDSA P-256 signatures, signing replies with the computer's key |
| `sha2` | 0.10.9 | pairing commitment, 6-digit code, digests of what the phone confirms |
| `base64` | 0.22.1 | protocol encoding |
| `rand` | 0.8.8 | pairing codes and ids |
| `qrcode` | 0.14.1 | pairing QR code (SVG) |
| `keyring` | 4.2.0 | the pairing secrets in the system's credential store (Keychain, Windows Credential Manager, Secret Service) |
| `x25519-dalek` | 2.0.1 | the public half of the phone's Tor client key, written for `tor` |

The desktop apps' wallet page (`desktop/wallet-page`, docs/desktop/wallet.md), bundled into `dist/` and embedded in both apps;
exact versions in `package.json`, every transitive one in `package-lock.json`:

| Library | Version | Used for |
|---|---|---|
| `@near-wallet-selector/core`, `modal-ui`, `my-near-wallet`, `meteor-wallet`, `here-wallet`, `intear-wallet` | 10.1.4 | connecting the person's own NEAR wallet for a pool deposit |
| `buffer` | 6.0.3 | `Buffer` in the browser (the message nonce) |
| `esbuild` | 0.28.2 | bundling the page (build only, not shipped) |
| `serde`, `serde_json` | 1.0.229, 1.0.154 | JSON |

Build tooling, not shipped: `.github/workflows/release.yml` builds the apps on GitHub's machines with Rust 1.99.1,
`tauri-cli` 2.12.4 (installed with `--locked`) and the GitHub actions `actions/checkout` v7.0.1,
`actions/upload-artifact` v7.0.2 and `actions/download-artifact` v8.0.2, each pinned to its commit
([docs/RELEASE.md](docs/RELEASE.md)).

Test tooling, not shipped: C Tor 0.4.9.16 (Homebrew) runs the test onion service on the developer's Mac.
The iOS app (`ios/ONA`) uses only Apple frameworks (SwiftUI, Foundation, CryptoKit, Security, VisionKit). The mock
computer (`ios/MockComputer`) uses only the Python standard library; its P-256 code (`p256.py`) is written for the mock
only and is not meant for real keys.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Hugo Thomas & Enzo Blain.
