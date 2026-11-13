# Install and run

Tested only on macOS on Apple Silicon, with Rust 1.99.1. Other platforms are untested.

## Prerequisites

Rust 1.99.1 with the `wasm32-unknown-unknown` target. The contract hashes depend on the exact compiler version, so install
that version by name once (this downloads it):

```
rustup toolchain install 1.99.1 --profile minimal --target wasm32-unknown-unknown
```

The repository has no `rust-toolchain.toml` yet: until it has one, check that `rustc --version` prints 1.99.1, or run the
commands with `cargo +1.99.1`. A `rust-toolchain.toml` naming 1.99.1 would make rustup download that version, or its wasm
target, on a machine that does not have it under that name, even when the `stable` toolchain is the same version.

A C compiler is also needed, for `blst`. On macOS: `xcode-select --install`.

## Check everything

```
cargo fetch
cargo fetch --manifest-path desktop/OnaCoreBridge/Cargo.toml
./verify.sh
```

The two `cargo fetch` download, once and online, the exact versions the lock files list: the lock check below runs offline and
stops with `no matching package named …` on a machine that never downloaded them.

It first checks the `Cargo.lock` of each desktop app (`desktop/OnaCoreBridge`, `desktop/tauri/src-tauri`), which are built outside
the workspace: each must match its `Cargo.toml`, and a package shared with the root must have the root's version within the same
compatible series (an older major version that only a desktop library needs is allowed). When `ona-core` gains a dependency, this
step fails and prints the command that updates the lock:

```
cargo update --manifest-path desktop/OnaCoreBridge/Cargo.toml --workspace
```

(the same with `desktop/tauri/src-tauri/Cargo.toml` for the Tauri app; a version that differs from the root is aligned with
`cargo update --manifest-path … -p <name>@<version> --precise <root version>`). When some crates of the Tauri app (Tauri itself,
`qrcode`) are not in the offline cache, cargo cannot check its lock: the step says so, prints any version that differs from the root as
a warning, and goes on.

It then runs all tests with the locked dependency versions (`--locked`), compiles the three contracts to wasm with every local path
rewritten, fails if a wasm still names a local directory or the user, and prints the SHA-256 of each contract. It needs no key, no
funded account, no Docker and no browser. How to compare these hashes with a deployed contract is in
[SPEC.md](../SPEC.md#reproducing-the-contract-hashes).

To type-check only, use `cargo check --workspace --all-targets`. Plain `cargo check` fails on purpose: `near-sdk` refuses to build
a contract for a native target outside tests.

## Try it

A full mission against a fake model, a fake web and fake payments:

```
cargo run -p ona-core --bin ona -- demo
```

Without `demo`, `ona` reads one JSON request per line on stdin and prints one JSON reply per line. Every reply says `"mode":"mock"`.
A line that is not UTF-8 or is longer than 64 KiB gets an error reply. `open` takes an optional `protected` list of terms (names,
identifiers) to replace by pseudonyms before anything goes to the model. `prepare_payment` without `amount` pays the chosen offer's
price at the policy's rate; with `amount`, it must be that same amount. It returns the fields of the confirmation digest (`payment`) and
the digest to send back with `confirm_payment`.

### The pool commands

With these variables set, `ona` also answers `pool_portfolio`, `pool_prepare`, `pool_execute`, `pool_recover`,
`pool_request_exit` and `pool_escape_exit` (inputs,
outputs and the confirmation flow: [docs/desktop/pool-commands.md](desktop/pool-commands.md)). They read the pool contract, views
only, and never contact the relay. Agent calls go to `ona-agent` (see "Run the pool agent") when `ONA_POOL_AGENT_URL` is set;
without it `pool_execute` answers `no connection to the pool agent yet` and no agent call is made. The commands have run only
against a fake pool, with a fake agent and with the real agent over HTTP on this machine. A deposit's `pool_execute` runs twice: the
first call returns `sign_message`, which the depositing account's own wallet must sign (NEP-413 `signMessage`, recipient the pool),
and the second carries `depositor_signature`. **Do not send a pool deposit from a wallet until an agent runs for that pool**: nobody
could turn it into cash notes, and it would wait in the contract for a refund.

| Variable | Value |
|---|---|
| `ONA_WALLET_FILE` | the encrypted wallet file, created if missing. Without it the pool commands answer `no pool wallet configured` |
| `ONA_WALLET_KEY_FILE` | a file holding the wallet key as 64 hex characters, readable by its owner only |
| `ONA_POOL` | the pool contract account |
| `ONA_RPC_URL` | NEAR RPC endpoint, `https` (plain `http` to this machine only). Through Tor (`ONA_TOR_SOCKS`, see "Go through Tor"): `https` to a host name, or `http` to an onion service |
| `ONA_RPC_URL_2` | optional, a second NEAR RPC endpoint run by another operator: `pool_recover` decides a note's fate only when both agree. Without it the first endpoint is trusted |
| `ONA_POOL_RECOMMENDED_NEAR` | optional, the deposit amounts the app recommends, whole NEAR separated by commas, each at least 0.1 NEAR; default `100,500,2000`. A deposit of another amount is still allowed, with a warning |
| `ONA_POOL_AGENT_URL` | optional, the pool agent's address, `https` (plain `http` to this machine only; through Tor, `https` to a host name or `http` to an onion service). Requests follow no redirect and ignore proxy variables. Without it, agent calls are refused |

A fake relay on localhost, for front-end work:

```
cargo run -p ona-server --bin ona-mock-relay -- 8787
```

Its startup output gives the request key and domain tag. Routes, all `POST` with a JSON body:

| Route | Body | Reply |
|---|---|---|
| `/dev/credit` | `{}` | a free test credit: `token`, `owner_sig`, `expires_at` (the claim signature's expiry, valid a day), and `owner_key`, the credit's owner key, so that the front end can sign `exchange_sig`. Exists only in this binary |
| `/exchange` | `token`, `owner_sig`, `expires_at`, `exchange_sig`, `blinded` (8 points), all hexadecimal in lowercase except `expires_at` (nanoseconds, as a decimal string) | 202 while pending, then 200 with `signatures` when the same request is repeated; 410 if the claim expired before it reached the chain (send it again with a later `expires_at` and the same blinded points: the first claim may still land, and then only those points are signed) |
| `/chat` | `token` (hex, 80 bytes), `prompt` | `reply`, `tokens_used`, `mode` |

## Use the real model

`ona real` works like plain `ona`, but the planner and the page reader call a real model through a relay. Every call spends credits.
Nothing selects this mode by default: without the word `real`, or with any required variable missing, no real call is made.

| Variable | Value |
|---|---|
| `ONA_REAL_RELAY_URL` | relay address: `https`, or `http` on `127.0.0.1` or `localhost` only. Through Tor: `https` to a host name, or `http` to an onion service; an onion address is refused without Tor |
| `ONA_REAL_MODEL` | model name, which the relay must allow |
| `ONA_REAL_MAX_TOKENS` | ceiling on the reply tokens of one call, at most the relay's own limit. The prompt counts on top of it |
| `ONA_REAL_TOKEN_BUDGET` | most tokens in total for this run of `ona`, prompts and replies, at least one call's ceiling |
| `ONA_REAL_TOKENS_FILE` | optional, a file with one request token per line, one spent per call and removed from the file before it is sent. Refused if empty or readable by other accounts (`chmod 600`). Only one `ona real` can use a file at a time: a lock file `<file>.lock` is created next to it. `ona-relay` refuses a chat without one |

On 13/11/2026 a mission ran this way with `z-ai/glm-5.3-flash`, through Tor to the team's test relay (an onion service with
client authorization): the plan and both page readings came from the model, 3 calls, 4,187 tokens. With `ONA_REAL_MAX_TOKENS=512`
the page readings failed: the model spent the whole ceiling thinking and replied with no content; 2048 was enough. The first
connection to the relay's onion service took about a minute, longer than `ona`'s timeout, and the next ones were quick.

**Until the enclave quotes are verified in this client, the relay can read the content of a mission and make up replies. Do not run a
sensitive mission in this mode.** Proxy variables of the environment (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are ignored and
redirects are not followed. `ona real` connects to the relay directly unless `ONA_TOR_SOCKS` is set (see "Go through Tor").

```
cargo run -p ona-core --bin ona -- real
```

### Go through Tor

With `ONA_TOR_SOCKS` set, **everything** `ona` sends to the network goes through that local Tor daemon: the relay (`ona real`), the
pool agent and the NEAR RPC nodes of the pool commands. Without it, `ona real` and the pool commands print on stderr, at start, that
the relay, the agent and the RPC nodes see this computer's IP address. `ona demo` and plain `ona` without a pool touch no network.

| Variable | Value |
|---|---|
| `ONA_TOR_SOCKS` | optional, the SOCKS port of a `tor` running on this machine, `ip:port`, for example `127.0.0.1:9050`. A proxy on another machine is refused |
| `ONA_REQUIRE_TOR` | optional, `1` makes `ona` refuse to start when `ONA_TOR_SOCKS` is not set; `0` or unset does not |

Through Tor:
- host names go to Tor unresolved (SOCKS5 with remote resolution); nothing is looked up on this machine;
- every request gets its own random SOCKS user name and password, so with Tor's `IsolateSOCKSAuth` (on by default) each request has
  its own circuit: a cash issue, which names the depositing account, and an entry into a vault never share one, nor do two RPC
  reads. This is Tor's documented behaviour, not verified on the real Tor network;
- if Tor is down or refuses a connection the request fails: nothing is retried directly. Proxy variables of the environment are
  ignored and redirects are not followed;
- destinations must be `https` to a public host name or `http` to a version 3 onion service: a local address (`127.0.0.1`,
  `localhost`), an IP address or plain `http` to the internet is refused before anything is sent. Without Tor, an onion address is
  refused, so its name never reaches the local resolver.

A minimal `torrc` for the client (`tor -f torrc`, then wait for `Bootstrapped 100%`):

```
SocksPort 127.0.0.1:9050
SafeSocks 1
```

`SafeSocks 1` makes Tor refuse a request carrying an IP address. `docs/torrc.client.example` and [docs/TOR.md](TOR.md) have more.
None of this has run on the real Tor network: only against a fake SOCKS server on this machine.

Each call reserves its reply ceiling plus one token per byte of prompt before it is sent. That reservation stays spent if the call fails,
and only the usage in a validly signed reply replaces it, so the real cost of a call can exceed the ceiling. A mission is limited to 4 KB and
a page to 32 KB. The budget is counted in memory, so restarting `ona` starts it again. A call stops before sending when the budget or the
request tokens run out, and the model stops after three failures in a row where nothing was sent. Only the model is real: the web and
the payments stay fake, and those replies still say `"mode":"mock"`. For each real call the journal keeps the response id, the model,
the token count and salted fingerprints, never the content. The exposure report counts real and fake calls apart (`model_calls_real`,
`model_calls_mock`, `real_calls`), and its `mode` is `mixed` when real calls and fake parts are both present. Its `parties` list names the
relay and the model with the requests and bytes each received, attestation and signature requests included, and
`content_readable_by_relay` is `true` as soon as one request reached the relay. This mode has never run against NEAR AI.

To check one encrypted call against NEAR AI without a mission, run a relay that holds the key, then:

```
ONA_CHECK_RELAY_URL=http://127.0.0.1:8787 ONA_CHECK_MODEL=<model> cargo run -p ona-core --example e2ee_check
```

| Variable | Value |
|---|---|
| `ONA_CHECK_RELAY_URL` | relay address, default `http://127.0.0.1:8787` |
| `ONA_CHECK_MODEL` | model name, required |
| `ONA_CHECK_MAX_TOKENS` | optional, most reply tokens, default 200 |
| `ONA_CHECK_VERSION` | optional, `2` to compare with encryption version 2; version 3 otherwise |

It prints whether the reply was decrypted and its signature checked. One run spends at most the reply ceiling plus the prompt.

## Measure gas on a local node

```
./verify.sh
NEAR_SANDBOX_BIN_PATH=/path/to/near-sandbox cargo run -p ona-sandbox
```

`NEAR_SANDBOX_BIN_PATH` is required and must name a `near-sandbox` binary you obtained and checked yourself: without it the
`near-sandbox` crate would download one and run it without checking a checksum, so `ona-sandbox` stops instead. This deploys the contract
on a local node, calls every method, prints the gas burnt, then runs the real signer loop and a real relay exchange against the node.
The signer and the relay read that one node as both of their endpoints, which their programs refuse: only this test run does it. The
owner signatures it sends expire one hour after the node's latest final block. It has not been run since the contract and the relay
changed, so the gas table in SPEC still holds the earlier measurements. The node crashes when started inside a macOS Seatbelt sandbox,
so run it from a normal terminal.

### The pool and its agent on a local node

```
./verify.sh
NEAR_SANDBOX_BIN_PATH=/path/to/near-sandbox cargo run -p ona-sandbox --bin ona-sandbox-pool
```

`verify.sh` builds `ona-pool` and `ona-test-staking`, a **test stand-in** for a staking pool (the standard staking pool of
`near/core-contracts` is not available offline). It is deployed only by this program and applies the rules of the strict mock of the
pool's tests: no `unstake` above what is staked, no `withdraw` above what is unstaked nor before a lock of 120 seconds of block time
after the last `unstake`. The program then, on one local node:

1. deploys `ona-pool` with the plan of `ona-deploy pool` (three cash tiers, escape delay two hours, owner signatures valid one hour instead of the client's 24, so the escape step is reached in one short fast-forward) and the test staking pool, lists it
   as vault 0, and moves the node's clock past the admin delay (`sandbox_fast_forward`). It deploys the pool's test build
   (`ona_pool_short_admin_delay.wasm`, built by `verify.sh`) with an admin delay of two minutes: with the normal build's 7 days,
   the wait would take about 3 h 30 (estimated on 12/11/2026 from about 50 blocks per second, each adding about one second of
   block time, read twice from the node on an Apple Silicon Mac);
2. starts the agent in the same process, from the `ona-agent` library (its `Agent`, its HTTP API and the relay's HTTP front, as
   `ona-agent run`), reading the one node as both of its endpoints, which `ona-agent run` refuses: only this test run does it. The
   program ticks the agent and moves the clock forward instead of waiting, with batches of one request and no delay;
3. runs the user's side through `ona-core`'s pool commands and `HttpAgent`: a 12 NEAR deposit from the depositor's own account and
   the cash issue against its wallet signature, an entry into vault 0, the planner's placement, a reward on the test pool and the
   planner's sync, a leave to cash that waits for the planner to unstake and withdraw, a payment to the depositing account;
4. stops the agent, waits out the escape delay and checks the fallback: the client keeps an unsent note spending, then holds it again;
   anyone pays cash notes by `escape_exit`, with and without a listed request; anyone brings the vault's funds back (`unstake` and
   `withdraw` with amounts fixed by the contract) and pays a share note.

It stops at the first step that fails, names it, and prints what was verified before, then the gas burnt by every transaction,
the agent's included, as a table ready for SPEC. Run to the end on 13/11/2026: 34 checks passed, escape exits included; the gas measured is in SPEC.
The deposit's wallet signature is made with the agent's own NEP-413 layout, so the run does not check that layout against a real
wallet. Run it from a normal terminal, as above.

With `--serve`, the program stops after the deposit and the cash issue, writes a wallet, its key and a `pool.json` for a desktop
app (development build, `"local_node": true`) into `ONA_SANDBOX_DIR` (default: a folder in the system's temporary directory), and
keeps the node and the agent running until Ctrl-C, ticking the agent every two seconds and moving the node's clock ten seconds
each time:

```
NEAR_SANDBOX_BIN_PATH=/path/to/near-sandbox ONA_SANDBOX_DIR=/some/folder cargo run -p ona-sandbox --bin ona-sandbox-pool -- --serve
```

Copy that `pool.json` into the app's data folder. Run on 12/11/2026 (near-sandbox 2.13.4, Apple Silicon Mac): the Tauri app's
engine read 12 NEAR of cash, prepared and sent an entry of 10 NEAR into vault 0, and `pool_recover` collected the share notes
(an ignored test, `local_pool_through_the_engine`, run by hand with `ONA_TEST_POOL_DIR`).

## The NEAR RPC endpoint

Every program here talks to NEAR through `ona-near`, and **trusts the RPC node it is given**: the deposits the signer signs for, the
claims the relay accepts and the checks of `ona-deploy` all rest on what the node answers, and no proof is checked. Use a node you run
yourself, or one you trust as much as the keys it serves. The signer and the relay read through two endpoints and stop when they
disagree (see below), which removes the need to trust one of them, not both. One account key should be used by one program at a time: two programs sending
with the same key read the same nonce, and one of them is refused.

- `ONA_RPC_URL` must start with `https://`. Plain `http://` is accepted only to `127.0.0.1`, `localhost` or `[::1]` (a local node);
  only a client that goes through Tor (for `ona`, `ONA_TOR_SOCKS`) also accepts it to a `.onion` address. Redirects are not followed, and the `HTTPS_PROXY`,
  `HTTP_PROXY` and `ALL_PROXY` variables are ignored.
- When a transaction gets no clear answer (a timeout, an HTTP error, a result that is not stated final), the client asks the node a few
  times what became of it, and never sends it again. If the node still cannot say, the error gives the transaction hash: check it on an
  explorer before doing anything that would repeat it, because it can still be included.
- `ona-deploy` and `ona-crowd run` count a transaction as failed when any of its receipts failed, including a payment or a call the
  contract did not wait for.

## Deploy the contracts

Testnet or a local node only. Mainnet is refused from the names given, from a `.near` parent account, and from the chain id the node
reports, which is asked before anything is sent. Build the contracts with `verify.sh`, and create the signer keys as below. Each
contract becomes `mint.<parent>`, `registry.<parent>` or `pool.<parent>`, created and initialized in one transaction, with no access key.
None of them has been deployed on testnet yet, and the pool has never been deployed anywhere.

Before sending, the tool checks that every role account is well formed, exists and holds only one role, then prints the plan (roles,
funding, size and SHA-256 of the contract) and **waits for you to type the new account name** on the terminal. After the deployment it
checks that the account holds no access key and that the code it runs has the SHA-256 of the file sent, and prints the transaction hash.

| Variable | Value |
|---|---|
| `ONA_RPC_URL`, `ONA_NETWORK` | NEAR RPC endpoint, and the network name written into the contracts |
| `ONA_CHAIN_ID` | optional, the chain id the node must report, default the value of `ONA_NETWORK`. For a local node, the id it reports (for example `localnet`, not verified) |
| `ONA_PARENT_ACCOUNT`, `ONA_PARENT_KEY_FILE` | funded parent account (ending in `.testnet` on testnet), and its key in a regular file that belongs to you and only you can read (a symbolic link is refused) |
| `ONA_SIGNER_KEYS_FILE` | mint only: the file from `ona-signer init-keys` |
| `ONA_SIGNER_ACCOUNT`, `ONA_RELAY_ACCOUNT` | mint only: two of the roles |
| `ONA_GUARDIAN_ACCOUNT` | mint and pool: the guardian |
| `ONA_REGISTRY_OWNER_1`, `ONA_REGISTRY_OWNER_2`, `ONA_AGGREGATOR_ACCOUNT` | registry only |
| `ONA_AGENT_ACCOUNT` | pool only: the account allowed to place funds and pay exits, different from the guardian |
| `ONA_ESCAPE_DELAY_SECS` | optional, pool only, seconds without agent activity before anyone can pay exits, from 60 to 30 days, default 7 days |
| `ONA_ADMIN_DELAY_SECS` | optional, pool only, seconds before a new agent, vault or fee takes effect, from 7 to 30 days, default 7 days. From one minute with the pool's test build (`ONA_POOL_WASM=target/wasm32-unknown-unknown/contract/ona_pool_short_admin_delay.wasm`), for testnet only: holders then have no time to leave before a change |
| `ONA_POOL_CASH_TIERS` | pool only: a JSON file listing the cash notes, `[{"value": "<yoctoNEAR>", "pk_g2": "<base64 of the 96-byte compressed key>"}]`, 1 to 8 tiers, each key used once, each value above 0.004 NEAR |
| `ONA_CASH_HOURLY_CAP` | pool only: most yoctoNEAR the cash exits may pay per hour, at least two of the largest cash notes |
| `ONA_MAX_RATE_BPS` | optional, pool only: yearly growth of each account's exit limit in basis points, at most 10000, default 2000 |
| `ONA_MIN_LIVE_NOTES` | optional, pool only: live notes a cash tier must have before the agent spends or pays one of them, at least 1, default 5 |
| `ONA_FUNDING_NEAR` | optional, NEAR sent to the new account, default 5 |
| `ONA_BASE_VALUE_MILLI_NEAR` | optional, mint only, value of the lowest tier, default 100 |
| `ONA_CIRCULATION_CAP`, `ONA_HOURLY_REDEEM_CAP` | optional, mint only, per tier, default 1000 and 100 |
| `ONA_MINT_WASM`, `ONA_REGISTRY_WASM`, `ONA_POOL_WASM` | optional, paths to the built contracts |

```
cargo run -p ona-deploy -- mint
cargo run -p ona-deploy -- registry
cargo run -p ona-deploy -- pool
```

The pool starts with no vault. The guardian then lists each staking pool with `add_vault`, giving the SHA-256 of the code it checked
there and one share-note key per tier; creating and holding those keys, and the cash keys, for the agent is not built yet. Lending
vaults are refused, and a staking pool can serve one vault only. A new vault, agent or fee takes effect only after the admin delay,
and anyone can leave in the meantime. Depositors pay the pool through its `deposit` method, at least 0.1 NEAR; a plain transfer is
never credited to anyone. The agent turns deposits into cash notes (`issue_cash`), cash into a vault's shares (`enter`), shares back
into cash (`leave`, from the vault's liquid funds, which is also how a holder changes vault), and pays cash notes (`pay_exit`).

## Run the signer

```
cargo run -p ona-signer -- init-keys signer-keys.bin 8
```

This creates the mint keys in a new private file, and prints the public keys to give to the contract at deployment. Each deployment
needs its own keys. To issue tokens:

| Variable | Value |
|---|---|
| `ONA_RPC_URL` | NEAR RPC endpoint, `https` (plain `http` to this machine only); transactions are sent here |
| `ONA_RPC_URL_2` | a second NEAR RPC endpoint, run by another operator; every read must agree with the first |
| `ONA_CHAIN_ID` | the chain id both endpoints must report (for example `testnet`); mainnet is refused |
| `ONA_MINT` | account of the deployed contract |
| `ONA_SIGNER_ACCOUNT` | account named as signer in the contract |
| `ONA_SIGNER_ACCOUNT_KEY_FILE` | file holding `ed25519:<base58>`, readable by its owner only |
| `ONA_SIGNER_KEYS_FILE` | the file from `init-keys` |
| `ONA_SIGNER_STATE_FILE` | where the signer records its progress, readable by its owner only; must survive restarts |

```
cargo run -p ona-signer -- run
```

It refuses to start if its keys are not the ones the contract verifies against, if the two RPC URLs name the same endpoint, if an
endpoint reports another chain, if the state file belongs to another contract or keys or other users can read it, if another signer
holds it, or if the state file is new while the contract holds locked deposits (restore the old file instead: it remembers which
signatures were already published). Each pass reads at one final block known to both endpoints, at most 20 blocks apart, and never
below the highest block already used, which the state file keeps; any difference stops the pass. Two endpoints that lie together are
not detected. A pass looks at most 512 deposits and 2048 record ids ahead of its cursor; what lies beyond waits for the next pass. A
locked deposit it never published and cannot sign is unlocked, so it refunds at its deadline. Key files written by an earlier version,
without a type line, are refused.

## Run the relay

```
cargo run -p ona-server --bin ona-relay -- init-key relay-request-key.bin relay-store.log
```

This creates the request key and the store bound to it, both readable by their owner only; if the store cannot be created, the key file
is removed again. The relay never creates a store by itself: a lost or replaced store would make every used request token valid again,
so it refuses to start instead. Run one relay process per store; a second one is refused, and deleting `relay-store.log.lock` while the
relay runs stops its store until a restart.

To serve, on `127.0.0.1` only:

| Variable | Value |
|---|---|
| `ONA_RPC_URL` | NEAR RPC endpoint, `https` (plain `http` to this machine only); transactions are sent here |
| `ONA_RPC_URL_2` | a second NEAR RPC endpoint, run by another operator; every read must agree with the first |
| `ONA_MINT` | account of the deployed contract |
| `ONA_NETWORK` | network name used when the contract was created |
| `ONA_CHAIN_ID` | optional, the chain id both endpoints must report, default the value of `ONA_NETWORK`; mainnet is refused |
| `ONA_RELAY_ACCOUNT` | account named as relay in the contract |
| `ONA_RELAY_ACCOUNT_KEY_FILE` | file holding `ed25519:<base58>`, readable by its owner only |
| `ONA_RELAY_REQUEST_KEY_FILE` | the key file from `init-key` |
| `ONA_RELAY_STORE_FILE` | the store file from `init-key`; must survive restarts |
| `ONA_MODELS` | allowed models, separated by commas, none empty |
| `NEAR_AI_CLOUD_API_KEY` | NEAR AI key. Set it with `read -s`, never in a file. Removed from the environment once read |
| `ONA_RELAY_PORT` | optional, default 8787 |
| `ONA_FLUSH_SECS` | optional, seconds between batches of claims, default 60 |
| `ONA_TOKENS_PER_CREDIT` | optional, default 100 |
| `ONA_MAX_TOKENS` | optional, most tokens per reply, default 512 |
| `ONA_MAX_PROMPT_BYTES` | optional, most bytes of text in a chat message, default 4096. A reply is withheld above `ONA_MAX_TOKENS` + this + 64 tokens, so price a request token for that much |

```
cargo run -p ona-server --bin ona-relay -- run
```

It serves 32 connections at a time and keeps 256 waiting; beyond that it answers 503. A connection has 5 seconds for its request
line and headers and 30 for the whole request, so 32 slow clients can still keep it busy: put it behind an onion service with its
denial-of-service protection. An exchange (`POST /exchange`) carries the credit, its claim signature with `expires_at` (between 30
minutes and 7 days ahead), and `exchange_sig`, the owner's signature of the blinded points; a claim that could not reach the chain
before its expiry is given up and answers 410. An attestation needs an unused request token (`X-Ona-Token`), which it does not spend:
4 per token, and 600 per minute across all clients. A signature needs the request token spent on the chat it signs, for that reply's
`id`: 4 per chat for 10 minutes, a fetch the service does not answer is not counted, and the global limit never refuses it. The same
token on the attestation, the chat and the signature lets the relay link these three requests, as it already could from their timing.
If the store reports a write error, every further write is refused until the relay is restarted.

## Run the pool agent

**Never run against a real chain yet, and not in an enclave: whoever runs it sees which note asks for which vault.**

```
cargo run -p ona-agent -- init-keys agent-keys.bin 3 3 3
cargo run -p ona-agent -- init-store agent-keys.bin agent-store.log <pool account>
```

`init-keys <file> <cash tiers> [<tiers of vault 0> ...]` creates the blind-signing keys in a new private file and prints their
public halves (base64, the `pk_g2` the contract takes): give the cash keys to `ona-deploy pool` (`ONA_POOL_CASH_TIERS`) and each
vault's keys to `add_vault`. Every key serves one tier only. `init-store` creates the agent's store, bound to those keys and that pool.
The agent never creates a store by itself, and runs one process per store. To serve, on `127.0.0.1` only:

| Variable | Value |
|---|---|
| `ONA_RPC_URL` | NEAR RPC endpoint, `https` (plain `http` to this machine only); transactions are sent here |
| `ONA_RPC_URL_2` | a second NEAR RPC endpoint, run by another operator; every read must agree with the first |
| `ONA_CHAIN_ID` | the chain id both endpoints must report (for example `testnet`); mainnet is refused |
| `ONA_POOL` | the pool contract account |
| `ONA_AGENT_ACCOUNT` | the account named as agent in the pool |
| `ONA_AGENT_ACCOUNT_KEY_FILE` | file holding `ed25519:<base58>`, readable by its owner only |
| `ONA_AGENT_KEYS_FILE` | the key file from `init-keys` |
| `ONA_AGENT_STORE_FILE` | the store file from `init-store`; must survive restarts |
| `ONA_AGENT_PORT` | optional, default 8788 |
| `ONA_AGENT_PER_MINUTE` | optional, requests per minute per route for all clients together, default 120 |
| `ONA_AGENT_TICK_SECS` | optional, seconds between two ticks (sending the window's batch, settling open requests, the planner, the purge), default 60; keep it well below `ONA_AGENT_WINDOW_SECS` |
| `ONA_AGENT_WINDOW_SECS` | optional, length of a processing window, default 900; windows alternate between entries and leaves, and cash exits; above 0 |
| `ONA_AGENT_MIN_BATCH` | optional, ready requests of a window's class needed before any of them is sent, default 5; above 0 |
| `ONA_AGENT_MIN_DELAY_SECS` | optional, least time a request waits after it arrives, default 600 |
| `ONA_AGENT_JITTER_SECS` | optional, a random wait between 0 and this is added to each request, default 3000 |
| `ONA_AGENT_RETENTION_SECS` | optional, finished records and signatures are deleted this long after they finished, default 604800 (7 days) |
| `ONA_AGENT_ISSUES_PER_HOUR` | optional, cash issues one account may ask for per hour, default 6 |
| `ONA_AGENT_RESERVE_PERCENT` | optional, percent of each vault's assets kept liquid, on top of what queued leaves will take, default 20 |
| `ONA_AGENT_SETTLEMENT_SECS` | optional, money moves only at multiples of this period, default 1800 |
| `ONA_AGENT_MIN_ACTIVE` | optional, entries and leaves needed since the last settlement before the next one, default 10 |
| `ONA_AGENT_STEADY_SECS`, `ONA_AGENT_STEADY_YOCTO` | optional, unstake this amount from every vault at each multiple of this period, whatever the requests, default off; the period must be a multiple of 259200 (3 days, the contract's limit of one unstake of the agent's own per vault), otherwise the agent refuses to start; a line missed or blocked by a settlement is skipped |
| `ONA_AGENT_UNBOND_WAIT_SECS` | optional, how long unstaked funds wait before `withdraw`, default 4 days (the staking pool's real delay is not verified) |
| `ONA_AGENT_MIN_MOVE_YOCTO` | optional, smaller moves are not made, default 1 NEAR |

```
cargo run -p ona-agent -- run
```

It refuses to start if its keys are not the ones the contract verifies against, if the account is not the pool's agent, if the two
RPC URLs name the same endpoint or an endpoint reports another chain, or if its store is missing, belongs to other keys, or is held by
another process, or if `ONA_AGENT_WINDOW_SECS` or `ONA_AGENT_MIN_BATCH` is 0. Entries, leaves and cash exits wait in a queue and
leave in batches (see SPEC, Pool agent); with few users a request waits until enough others arrive, up to its owner's 24-hour
deadline, after which it is refused and the note freed. The crowd simulator (`crates/ona-crowd/PARADES.md`) models the settlement
and reserve rules on their own, not this agent's queue: its figures are not a measure of this program.

## Journal anchoring

`ona-anchor` is a library with no program yet, so there is nothing to configure or run. Its tests need no key and no node:

```
cargo test -p ona-anchor
```

When a program uses it, it will sign `anchor` with the account named as aggregator in `ona-registry`, through `ona-near`, attaching
0.01 NEAR per anchor for storage (the registry refunds the excess), and read each anchor back from a final block. The registry accepts
at most one anchor every 30 minutes, and the aggregator cannot be one of its owners. After deployment, the registry's owners call
`propose` (payable, storage), then `confirm(id, action)` for the other owner, or `emergency` alone to revoke a value or raise the
incident level; `propose_takeover` replaces a lost owner after 30 days unless it vetoes. A program using the aggregator should give
it a tag file (`Aggregator::with_tag_file`) on storage that survives restarts. Nothing new to configure.

## Simulate a crowd

At launch the pool is empty, so a real user has no one to hide among. `ona-crowd` creates fake users from a seed and runs the agent's
rules over them: at least `k` requests per vault before a batch, a minimum wait before placing, a minimum stay before any exit, batches
at a random moment within a window, and every amount in whole notes. Exit payments go one note at a time back to the account that
deposited, and never above what that account deposited (the cap is deposits plus gains; no gains are
simulated). How much each account puts in and takes out is public; what should stay private is which vault it chose and when the
agent placed for it.

```
cargo run -p ona-crowd -- simulate crowd.json out/
```

`crowd.json` needs at least the list of vaults; every other field has a default (see `Config` in `crates/ona-crowd/src/lib.rs`):

```
{"seed": 1, "users": 50, "vaults": [{"kind": "staking", "contract": "staking.example.testnet"}]}
```

It writes `out/timeline.json` (only what the chain shows), `out/truth.json` (which vault each user chose, kept apart to measure
privacy) and `out/keys.json` (the fake users' private keys, never printed). All three are new files readable by their owner only; an
existing file is never replaced. Choose an output folder outside the repository; `out/` and these file names are ignored by git anyway. For each depositor account, it counts the vaults and the placement batches still possible from the public timeline and
the pool's public rules, and how many accounts have only one possible vault. Batches are assigned jointly, since each holds exactly
the notes of its members. The figures are an upper bound on privacy: the elimination never removes the true vault, but a stronger
observer can remove more. Accounts never placed are counted apart. A fixed seed lets anyone rebuild every key and the ground truth,
so it is for demos and tests only.

`ona-crowd parades crowd.json [seeds]` compares the agent without countermeasures to a liquid reserve, net settlement, noise,
separate accounting, steady withdrawals and vault switching, over seeds 1 to 10 by default. `ona-crowd yield crowd.json [seeds]`
compares pooled and individual yield and suggestions; the configuration must give `yield_bp_per_hour`. Both add a Bayesian measure
(sampled assignments) to the elimination bound. Results and how to read them are in
[crates/ona-crowd/PARADES.md](../crates/ona-crowd/PARADES.md): varied deposit amounts are the main leak, and simulated yield cannot be
played on a chain.

`ona-crowd run crowd.json out/` also plays the timeline on a local node or testnet. **It has never run.** It ignores the configured
seed and draws a secret one from the system, never stored. It refuses mainnet, by name and by the chain id the node reports, and
lending vaults (no adapter yet). Before writing any file or sending anything, it computes everything the funder account will send and
stops if that is above `ONA_CROWD_MAX_SPEND_NEAR`. An error from the node stops the run; nothing is taken back from the fake accounts
or from staking. Every fake account is funded by the same account, so the crowd is recognizable on chain. The `ona-pool` contract is not used yet, so the agent account stands in for it with its own funds:
placement calls `deposit_and_stake` on a staking pool, withdrawal calls `unstake` (the funds stay locked for some epochs and are not
withdrawn), exit payments are transfers. The agent account is funded with what it places plus what it pays out. Deposits are real `deposit` calls on the mint, whose token secrets are written to
`out/tokens.txt` first. Each denomination must equal one tier of the mint exactly; the mint from `ona-deploy` doubles its tiers, so it
cannot serve 1, 10 and 100 at once.

| Variable | Value |
|---|---|
| `ONA_RPC_URL`, `ONA_NETWORK` | NEAR RPC endpoint and network name |
| `ONA_CHAIN_ID` | optional, the chain id the node must report, default the value of `ONA_NETWORK` |
| `ONA_MINT` | account of the deployed mint |
| `ONA_CROWD_MAX_SPEND_NEAR` | optional, most NEAR the run may send from the funder account, default 10 |
| `ONA_CROWD_FUNDER_ACCOUNT`, `ONA_CROWD_FUNDER_KEY_FILE` | account that funds the fake users and the agent, and its key in a file readable by its owner only |
| `ONA_CROWD_AGENT_ACCOUNT`, `ONA_CROWD_AGENT_KEY_FILE` | account that places, withdraws and pays, and its key |
| `ONA_CROWD_UNIT_MILLI_NEAR` | optional, value of one unit of the asset, default 100 |
| `ONA_CROWD_SPEED` | optional, simulated seconds per real second, default 1; 0 plays without waiting |

## Not available yet

No NEAR testnet deployment, tested real model connection, Tor, enclave, anchoring program, desktop app or iOS app. See the status table in the [README](../README.md).
