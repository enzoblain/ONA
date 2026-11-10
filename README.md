# ONA: an AI agent that reports who saw what during each mission

Built at NEAR HACKATHON · Tracks: to be confirmed · Network: NEAR testnet (planned) · Not audited

> **Status: early prototype, not audited.** The token crypto, the two contracts, the signer and relay logic, the wallet and the
> local mission core exist and pass their tests. They run against a simulated chain, a fake model and a fake web. The contracts have
> not yet run on a real NEAR node. **Do not use real funds.** See [what works today](#what-works-today).

## What it is

ONA runs an AI agent on your own computer for a sensitive task, and produces a per-mission **exposure report**: every party
that received something during the mission, and exactly what it received.

Example mission: find a labour lawyer and compare fee ranges on a generic version of your case, without telling the firms
you did not choose who you are.

## The problem

A hosted AI agent links your identity, your content and your actions at one operator. Encrypted inference helps with
content, but the requests, the payment and the agent's actions still identify you.

## Planned architecture

| Component | Role | Language |
|---|---|---|
| `ona-core` | Runs on the user's computer: mission state machine, payment gate, pseudonyms, E2EE client for NEAR AI Cloud, wallet tokens, sealed state, journal, exposure report, Tor client (Arti) | Rust |
| Desktop app | Connects a NEAR wallet for deposits, starts missions, asks for confirmations, shows the exposure report | Tauri + JavaScript |
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
| `ona-mint`, `ona-registry` contracts | done, gas not measured | mocked NEAR VM with real BLS and ed25519 host functions |
| `ona-signer` issuing loop | logic done, no RPC client | fake chain |
| `ona-server` relay | logic and HTTP done, no RPC client | fake chain and model |
| `ona-wallet` encrypted wallet file | done, keychain not wired in | native tests |
| `ona-core` mission, gate, sealed journal, 24-hour chat deletion | done | fake model, web and payments, each labelled `mode: mock` |
| Desktop app, iOS app | not in this repository yet | none |
| NEAR AI Cloud client, Tor, Phala enclave | not built | none |

## Run it

Setup and details are in [docs/INSTALL.md](docs/INSTALL.md). To contribute, see [CONTRIBUTING.md](CONTRIBUTING.md).

`./verify.sh` runs every test and compiles the contracts. It needs Rust and the `wasm32-unknown-unknown` target, and no key,
no funded account, no Docker and no browser.

```
cargo run -p ona-core --bin ona -- demo     # a full mission against the fakes
cargo run -p ona-server --bin ona-mock-relay -- 8787     # a fake relay on localhost for front-end work
```

To measure gas on a local node, build the contract as in `verify.sh`, set `NEAR_SANDBOX_BIN_PATH` to a `near-sandbox` binary, and run
`cargo run -p ona-sandbox`. This harness has not completed a run yet.

## Known limitations

- At launch the anonymity set is one, so ONA claims no unlinkability until a measured number of users is published.
- Deposits are public on chain and show that an account uses ONA.
- The model enclave reads the pseudonymized prompt by design, under a TEE assumption.
- NEAR AI Cloud keeps one usage row per request.
- The computer must be on for a mission to progress.
- The same team would operate the relay, the signer and the anchoring.
- Testnet only. The mint has no real-money deployment planned.
- A stolen signer key can drain the reserve at the speed of the hourly redemption limit. There is no key rotation.
- An attacker holding tokens can use up a tier's hourly limit and delay exits for that tier.

More in [SPEC.md](SPEC.md).

## Libraries and AI-generated code

Main libraries: `blst`, `near-sdk`, `near-sandbox`, `ed25519-dalek`, `sha2`, `chacha20poly1305`, `hkdf`, `serde_json`, `tokio`.

The code and tests in this repository were written with Claude (Anthropic), under human direction.

## Related project

To be named.

## License

To be added (MIT planned).
