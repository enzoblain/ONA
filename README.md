<img src="assets/logo.png" alt="ONA logo" width="120">

# ONA: a prototype AI assistant designed so that no single party receives both who asks and what is asked

Built at NEAR HACKATHON (1 to 14 November 2026) · Track: Privacy & Private AI · Network: NEAR testnet · MIT ·
**Prototype, not audited. Testnet only. Do not use real funds.**

ONA runs on your own computer. With a relay configured (the demo and the apps use fakes until then, labelled `mode: mock`),
the model receives your request with the names you protect replaced by pseudonyms, encrypted end to end for NEAR AI Cloud's
enclave, and only after the client has checked Intel's signature over that enclave. The relay in front of the model holds the
API key, so you need no account. With Tor enabled, the relay, the web and NEAR nodes see Tor traffic. Savings go through a NEAR
pool contract with blind notes, and money can only leave to an account that deposited.

## For automated reviewers

| | |
|---|---|
| Commit | the `main` branch; this text was checked against it on 14/11/2026 |
| Main route, nothing to download | `cargo run --locked -p ona-core --bin ona -- demo`, then `./verify.sh` (sequence below) |
| Prerequisites | macOS on Apple Silicon (the only platform tested), Rust 1.99.1 with the `wasm32-unknown-unknown` target, a C compiler (`xcode-select --install`). No key, no account, no Docker, no browser, no network after `cargo fetch` |
| Duration | the demo runs in under 1 s once built (measured 0.8 s on 14/11/2026, Apple Silicon Mac); building it and `./verify.sh` take minutes on a first run |
| Everything simulated says so | each JSON reply of the demo carries `"mode":"mock"` |
| The apps | optional: desktop installers on the [releases page](https://github.com/enzoblain/ONA/releases), not needed to check anything below |

Full sequence from a fresh clone:

```
rustup toolchain install 1.99.1 --profile minimal --target wasm32-unknown-unknown
rustup override set 1.99.1          # the repository has no rust-toolchain.toml
xcode-select --install              # once, for the C compiler blst needs
cargo fetch
cargo fetch --manifest-path desktop/OnaCoreBridge/Cargo.toml
./verify.sh
```

Without the second `cargo fetch`, `verify.sh` stops with `no matching package named …` (it checks the desktop lock file
offline). The last line of a passing run is:

```
All tests passed and the three contracts, the pool's test build and the test staking pool compile to wasm without local paths.
```

### State of each component (14/11/2026)

| Component | Status | Network | Test |
|---|---|---|---|
| Mission core (`ona-core`): plan, payment gate, pseudonyms, sealed journal, exposure report, research with checked quotes | built | none in the demo (all `mock`) | `cargo test -p ona-core`, the demo |
| Model client: end-to-end encryption v3 to NEAR AI Cloud, Intel TDX quote check (`dcap-qvl`) | built | real NEAR AI Cloud through the team's test relay: one encrypted call on 12/11, one mission and one research on 13/11 | `cargo test -p ona-core --test attestation --test quote --test e2ee` |
| Tor client | built | real Tor: the research of 13/11 went through it; the iPhone reached the computer's onion service on 11/11 and 14/11 | `cargo test -p ona-core --test tor` (fake SOCKS server) |
| `ona-pool` contract | built | **deployed on testnet** on 13/11 as `pool.ona-hugo.testnet` (test build, 2-minute admin delay), two test staking vaults | unit tests on a mocked VM; 34 checks on a local NEAR node |
| `ona-agent` pool agent | built | **ran on testnet** on 14/11, with demo settings (batches of one request, no delay), on the team's machine, not in an enclave | unit tests; the local-node run |
| Wallet deposit (Wallet Selector, NEP-413) | built in the desktop app | **used with a real wallet** (Meteor, testnet) on 14/11: deposit, cash notes, entry into vaults 0 and 1 | the testnet run |
| Crowd of test users (`ona-crowd-run`) | built | **ran on testnet** on 14/11: 8 test accounts each deposited and entered vault 1 | `cargo test -p ona-sandbox --bin ona-crowd-run` |
| `ona-mint` blind-token contract | built, gas measured | local NEAR node only, **not on testnet** | `cargo test -p ona-mint` |
| `ona-registry` and `ona-anchor` (journal anchoring) | contract and library built | **no program submits anchors**; not deployed | `cargo test -p ona-registry -p ona-anchor` |
| `ona-relay` (paid with blind tokens) | logic built | **the `ona-relay` program of this repository has not run yet**; the real calls of 12–13/11 went through a different, minimal test relay (a small script outside this repository that forwards encrypted requests to NEAR AI Cloud with the team's key, published as an onion service) | `cargo test -p ona-server` |
| Desktop app (Tauri) | built | runs the pool from the conversation on testnet (macOS, 14/11); started on GitHub's Windows and Linux machines, not used there | `cd desktop/tauri/src-tauri && cargo test --locked` |
| iPhone app | built | paired with the desktop app over Tor on a real iPhone 16 on 14/11; sending a message from it not verified | simulator and unit tests |

## Verify the claims

| ID | Claim | Command | Expected | Does NOT prove |
|---|---|---|---|---|
| C1 | A full mission runs, and the report lists every party with byte counts, never content | `cargo run --locked -p ona-core --bin ona -- demo` | last line (the exposure report, after `< `) contains `"content_readable_by_relay":false`, `"outputs":{"contact":1,"fetch":2,"search":1}`, `"pseudonyms_replaced":1`, `"mode":"mock"` | anything about a real model, web or payment: all are fakes here |
| C2 | Research answers with sources, and every note is quoted word for word from its page | `cargo run --locked -p ona-core --bin ona < docs/try/research.jsonl` | `research_result` with 4 notes, each `quote` equal to its `claim`, sources `s1`/`s2`; then `"outputs":{"fetch":2,"search":1}` | the quality of a real model's answer; the demo web has two fixed pages |
| C3 | The client refuses a model key unless Intel signed the quote and the quote binds that key and this request | `cargo test --locked -p ona-core --test attestation` | `12 passed; 1 ignored` (includes `the_client_sends_nothing_to_a_key_swapping_relay`) | the NVIDIA GPU evidence (not checked); what the enclave's code does with the prompt |
| C4 | The real NEAR AI quote passes Intel's check with live data | `cargo test --locked -p ona-core --test attestation -- --ignored` (needs the network) | `1 passed` | that today's NEAR AI machines still match: on 14/11 the app refused an unlisted deployment until three observed ones were added |
| C5 | Every Rust test passes and the contracts build deterministically for the pinned toolchain | `./verify.sh` | the last line above, and one `sha256` line per contract | the same hashes on another OS or Rust version (only macOS arm64 with 1.99.1 was checked) |
| C6 | The pool on testnet runs exactly the code of this repository | `curl -s -X POST https://test.rpc.fastnear.com -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"view_account","finality":"final","account_id":"pool.ona-hugo.testnet"}}'` | `"code_hash":"5YVda7B5T18ZnGj8E7EzWN1MjZ2U8M4i7BToRephVR4E"`, the base58 of the `ona_pool_short_admin_delay.wasm` sha256 that `verify.sh` printed on 14/11/2026 (`4380201c…989b`; convert with the command below) | that the contract is safe; it is not audited |
| C7 | The pool and agent run end to end on a local NEAR node, escape exits included | `NEAR_SANDBOX_BIN_PATH=/path/to/near-sandbox cargo run -p ona-sandbox --bin ona-sandbox-pool` (a `near-sandbox` 2.13.4 binary you checked) | each step named as it passes, then a gas table; 34 checks on 13/11/2026 | behaviour against a real staking pool (a test stand-in is used) |

Converting the sha256 of C6 to NEAR's base58 code hash:

```
python3 -c "a='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';f=lambda n:f(n//58)+a[n%58] if n else '';print(f(int('<sha256 printed by verify.sh>',16)))"
```

## The problem

People ask AI assistants about things they would not want tied to their name: a lawyer, a diagnosis, debts, a dispute at
work. The provider of a hosted assistant sees both who asks and what is asked, and so does every service the assistant acts
on (search engines, websites, payment providers). A privacy policy is a promise, not a mechanism.

## How ONA splits who from what

| Party | What it receives | What it does not receive, and why |
|---|---|---|
| The model (NEAR AI Cloud enclave) | the request, with declared names replaced by random 12-letter pseudonyms (`pseudonym.rs`) | your names, which are put back only on your computer; your IP address and account (the relay holds the key) |
| The relay | encrypted requests, their timing and sizes, the model name, token counts; it runs on the team's machine, outside any enclave | the content: requests are encrypted for the enclave (`e2ee.rs`), whose key is used only if its Intel TDX quote checks out (`attestation.rs`, `quote.rs`). The exposure report still marks `content_readable_by_relay: true` after a real call, because the client cannot prove what the relay did |
| Search engines and websites | the queries you confirmed, page requests, through Tor (`tor.rs`) | your IP address |
| The pool contract and its agent | deposits (public on chain) and blind notes | which vault a note came from when it leaves; exits go only to an account that deposited, one note at a time |
| The person you pay or write to | what you confirmed: you type the recipient, see the exact action, and confirm a digest of its fields (`gate.rs`) | anything you did not confirm |

After each conversation, the **exposure report** lists every party that received something, with request and byte counts,
never the content. The eight layers in plain terms, each with its state: [docs/PRIVACY.md](docs/PRIVACY.md).

## Track fit

Track `privacy` (Privacy & Private AI). Official hints and where they are in the code:

| Hint | In ONA |
|---|---|
| PRIVATE AI | pseudonyms before the model (`crates/ona-core/src/pseudonym.rs`), conversations kept in memory only by the apps, exposure report (`crates/ona-core/src/lib.rs`) |
| TEE | Intel TDX quote check with `dcap-qvl` before a model key is used (`crates/ona-core/src/attestation.rs`, `quote.rs`) |
| NEAR AI CLOUD | end-to-end encrypted client, encryption version 3 (`crates/ona-core/src/e2ee.rs`) |
| NEAR contracts | blind-note pool on testnet (`crates/ona-pool`), blind-token mint (`crates/ona-mint`) |

## Data handling

| | |
|---|---|
| Received from you | your question, the terms you protect, your confirmations |
| Sent | to the model: the pseudonymized request, encrypted; to the web: confirmed queries and page requests, through Tor when enabled; to NEAR: transactions your wallet signs, and agent requests carrying blind notes |
| Stored on your computer | the pool wallet (encrypted file), the sealed journal of each mission (for a real model call: response id, model, token count and salted fingerprints, not the content), the app's settings; the pseudonym table only while a conversation is open |
| Deleted | conversations when the app quits (the apps keep them in memory; a Tauri test checks that a conversation's text is in no file of the app's folder); the pseudonym table when the conversation closes |
| Stored by others | NEAR AI Cloud keeps one usage row per request; the agent keeps finished records for 7 days by default; deposits stay public on chain |

## Limitations

- **Testnet only**, with test staking pools as vaults. Nothing here has handled real money.
- **Small anonymity set.** The app shows how many identical notes yours blends in with ("blends in with at most N notes"),
  counted on chain; on testnet the crowd is 8 test accounts funded by one account, so it is recognizable on chain.
- **The agent and the relay run on the team's machine**, outside any enclave: the agent sees every request; the relay sees
  timing, sizes and token counts.
- **Not checked**: the NVIDIA GPU evidence; that the separation of Tor circuits holds on the real network (Tor's documented
  behaviour); a model deployment not seen before is refused.
- **Not built or not run**: the mint on testnet, the `ona-relay` program paid with blind tokens, anchoring, lending vaults.
- Every program trusts the NEAR RPC nodes it is given (no proofs); deposits show that an account uses ONA.
- Full list: [docs/DESIGN.md](docs/DESIGN.md#known-limitations); per component: [docs/STATUS.md](docs/STATUS.md).

## Nearest projects

- **NEAR AI Cloud's private inference**: ONA uses it for the model and adds what it does not cover: an account-free relay,
  pseudonyms before the enclave, Tor for the network address, confirmed actions, and an exposure report.
- **Hosted assistants with a no-log policy**: the provider still receives your account, your IP address and your text; ONA
  replaces the promise with encryption, pseudonyms and Tor.
- **Shielded pools on other chains**: they let funds leave to any address; ONA's pool pays exits only to an account that
  deposited, so it hides which vault you chose, not where your money goes.

## Try the apps (optional)

- Desktop installers (macOS, Windows, Linux): the [releases page](https://github.com/enzoblain/ONA/releases), built by the
  release workflow. The macOS build is signed with Developer ID and notarized when the team's Apple secrets are set,
  otherwise ad-hoc signed (allow it in macOS settings). The Windows and Linux builds were started on GitHub's machines,
  never used there.
- From source: `cd desktop/tauri/src-tauri && cargo tauri dev` (Tauri app); `desktop/OnaCoreBridge/build.sh` then
  `desktop/ONADesktop/ONADesktop.xcodeproj` (SwiftUI app, needs Xcode); iPhone: `ios/ArtiBridge/build-xcframework.sh` then
  `ios/ONA/ONA.xcodeproj`.
- In the apps, the model and the web are the demo ones (shown as `mode: mock`) until `model.json` names a relay
  ([docs/desktop/tauri.md](docs/desktop/tauri.md), "Real model"). The pool works on testnet once `pool.json` names the pool
  and an agent ([docs/INSTALL.md](docs/INSTALL.md)).

## Repository

| Path | What | Docs |
|---|---|---|
| `crates/ona-core` | the mission core: model client, gate, journal, research, pool client | [SPEC.md](SPEC.md), [docs/research.md](docs/research.md) |
| `crates/ona-mint`, `ona-pool`, `ona-registry` | NEAR contracts | [SPEC.md](SPEC.md) |
| `crates/ona-agent`, `ona-server`, `ona-signer` | pool agent, relay, signer | [docs/INSTALL.md](docs/INSTALL.md) |
| `crates/ona-token`, `ona-wallet`, `ona-near`, `ona-tor`, `ona-anchor`, `ona-crowd`, `ona-deploy`, `ona-sandbox`, `ona-test-staking` | tokens, wallet, NEAR client, Tor client, anchoring, crowd simulator, deployment, local-node and testnet runs, test staking pool | [SPEC.md](SPEC.md) |
| `desktop/ONADesktop`, `desktop/OnaCoreBridge` | macOS app (SwiftUI) and its bridge to the core | [docs/desktop/app.md](docs/desktop/app.md) |
| `desktop/tauri` | desktop app (Tauri), used on macOS, built for Windows and Linux | [docs/desktop/tauri.md](docs/desktop/tauri.md) |
| `desktop/wallet-page` | the page that connects the person's NEAR wallet | [docs/desktop/wallet.md](docs/desktop/wallet.md) |
| `ios/` | iPhone app, embedded Tor (Arti), a fake computer for tests | [docs/ios/app.md](docs/ios/app.md), [protocol](docs/ios/protocol-draft.md) |
| `site/` | the website, deployed at https://ona-indol.vercel.app | [docs/INSTALL.md](docs/INSTALL.md#the-website) |
| `.github/workflows/release.yml` | app builds on version tags, on pull requests that touch the apps or the core, and by hand; it does not run `verify.sh` | [docs/RELEASE.md](docs/RELEASE.md) |

All documents: [docs/README.md](docs/README.md).

## Built during the hackathon

The repository's history starts on 10/11/2026, inside the build window. Its first commit, "Import the ONA prototype",
brought what the team had built before that day: the first versions of `ona-core` (mission state machine, gate, journal,
page reader, chat vault), `ona-mint`, `ona-registry`, `ona-token`, `ona-wallet`, `ona-signer`, `ona-server` (relay logic and
a fake relay), `ona-sandbox` (gas measurement), about 12,000 lines. Everything after it is hackathon work, including the
pool contract and its agent, the testnet deployment, the model key check, the Tor client, research, pseudonyms, the three
apps, the phone protocol and the website. Team: Hugo Thomas (core, contracts, relay, pool) and Enzo Blain (apps, phone
protocol, Tor on iPhone, releases).

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

Website (`site/`), pinned exactly (`package-lock.json` pins the transitive ones). The site is deployed at https://ona-indol.vercel.app.

| Library | Version | Used for |
|---|---|---|
| `react`, `react-dom` | 19.3.1 | the three pages |
| `react-router-dom` | 7.18.5 | routes `/`, `/demo`, `/downloads` |
| `motion` | 14.12.0 | entrances and scroll reveals |
| `three` | 0.187.0 | the 3D opening of the home page: a liquid ghost (metaballs, with the `MarchingCubes` and `RoomEnvironment` helpers shipped in the package), the forest, the pit, the cave |
| `gsap` | 3.15.1 | the timelines of that opening (look around, jump, impact, re-forming) |
| `lenis` | 1.3.27 | smooth scrolling |
| Decrypted Text (React Bits, David Haz) | copied at commit `14330e6`, 2026-10-15 | the title of the landing page; one file, `site/src/components/reactbits/DecryptedText.tsx`, unchanged, under MIT + Commons Clause |
| Scanner (React Bits, David Haz) | copied at commit `cbfda76`, 2026-10-13 | a very faint backdrop behind the data and the install pages; `site/src/components/reactbits/Scanner.tsx` and `Scanner.css`, unchanged, same licence |
| `@number-flow/react` | 0.6.2 | animated figures |
| `@fontsource-variable/geist`, `@fontsource-variable/geist-mono` | 5.3.0 | fonts, served from the site itself |
| `vite`, `@vitejs/plugin-react`, `typescript`, `@types/react`, `@types/react-dom`, `@types/three` | 8.3.8, 6.3.0, 7.0.2, 19.3.0, 19.3.0, 0.187.0 | build only, not shipped |

Test tooling, not shipped: C Tor 0.4.9.16 (Homebrew) runs the test onion service on the developer's Mac.
The iOS app (`ios/ONA`) uses only Apple frameworks (SwiftUI, Foundation, CryptoKit, Security, VisionKit). The mock
computer (`ios/MockComputer`) uses only the Python standard library; its P-256 code (`p256.py`) is written for the mock
only and is not meant for real keys.

## Related project

Some team members also built **Moonpacks** at NEAR HACKATHON (tracks `nfts`, `memecoins`): memecoin card boosters,
a separate project with its own repository: https://github.com/ygk94/moonpacks. No code, contract or server is shared
between the two projects.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Hugo Thomas & Enzo Blain.
