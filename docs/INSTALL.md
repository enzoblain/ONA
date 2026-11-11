# Install and run

Tested only on macOS on Apple Silicon, with Rust 1.99.1. Other platforms are untested.

## Prerequisites

```
rustup target add wasm32-unknown-unknown
```

A C compiler is also needed, for `blst`. On macOS: `xcode-select --install`.

## Check everything

```
./verify.sh
```

This runs all tests with the locked dependency versions (`--locked`), compiles the three contracts to wasm with every local path
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

A fake relay on localhost, for front-end work:

```
cargo run -p ona-server --bin ona-mock-relay -- 8787
```

Its startup output gives the request key and domain tag. Routes, all `POST` with a JSON body:

| Route | Body | Reply |
|---|---|---|
| `/dev/credit` | `{}` | a free test credit: `token`, `owner_sig`. Exists only in this binary |
| `/exchange` | `token`, `owner_sig`, `blinded` (8 hex points) | 202 while pending, then 200 with `signatures` when the same request is repeated |
| `/chat` | `token` (hex, 80 bytes), `prompt` | `reply`, `tokens_used`, `mode` |

## Use the real model

`ona real` works like plain `ona`, but the planner and the page reader call a real model through a relay. Every call spends credits.
Nothing selects this mode by default: without the word `real`, or with any required variable missing, no real call is made.

| Variable | Value |
|---|---|
| `ONA_REAL_RELAY_URL` | relay address: `https`, or `http` on `127.0.0.1` or `localhost` only |
| `ONA_REAL_MODEL` | model name, which the relay must allow |
| `ONA_REAL_MAX_TOKENS` | ceiling on the reply tokens of one call, at most the relay's own limit. The prompt counts on top of it |
| `ONA_REAL_TOKEN_BUDGET` | most tokens in total for this run of `ona`, prompts and replies, at least one call's ceiling |
| `ONA_REAL_TOKENS_FILE` | optional, a file with one request token per line, one spent per call and removed from the file before it is sent. Refused if empty. `ona-relay` refuses a chat without one |

**Until the enclave quotes are verified in this client, the relay can read the content of a mission and make up replies. Do not run a
sensitive mission in this mode.**

```
cargo run -p ona-core --bin ona -- real
```

Each call reserves its reply ceiling plus one token per byte of prompt before it is sent. That reservation stays spent if the call fails,
and only the usage in a validly signed reply replaces it, so the real cost of a call can exceed the ceiling. A mission is limited to 4 KB and
a page to 32 KB. The budget is counted in memory, so restarting `ona` starts it again. A call stops before sending when the budget or the
request tokens run out, and the model stops after three failures in a row where nothing was sent. Only the model is real: the web and
the payments stay fake, and those replies still say `"mode":"mock"`. For each real call the journal keeps the response id, the model,
the token count and salted fingerprints, never the content. The exposure report counts real and fake calls apart (`model_calls_real`,
`model_calls_mock`, `real_calls`), and its `mode` is `mixed` when real calls and fake parts are both present. This mode has never run against NEAR AI.

## Measure gas on a local node

```
./verify.sh
NEAR_SANDBOX_BIN_PATH=/path/to/near-sandbox cargo run -p ona-sandbox
```

`NEAR_SANDBOX_BIN_PATH` is required and must name a `near-sandbox` binary you obtained and checked yourself: without it the
`near-sandbox` crate would download one and run it without checking a checksum, so `ona-sandbox` stops instead. This deploys the contract
on a local node, calls every method, prints the gas burnt, then runs the real signer loop and a real relay exchange against the node.
The node crashes when started inside a macOS Seatbelt sandbox, so run it from a normal terminal.

## The NEAR RPC endpoint

Every program here talks to NEAR through `ona-near`, and **trusts the RPC node it is given**: the deposits the signer signs for, the
claims the relay accepts and the checks of `ona-deploy` all rest on what the node answers, and no proof is checked. Use a node you run
yourself, or one you trust as much as the keys it serves. One account key should be used by one program at a time: two programs sending
with the same key read the same nonce, and one of them is refused.

- `ONA_RPC_URL` must start with `https://`. Plain `http://` is accepted only to `127.0.0.1`, `localhost` or `[::1]` (a local node);
  only a client that goes through Tor also accepts it to a `.onion` address. Redirects are not followed, and the `HTTPS_PROXY`,
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
| `ONA_ADMIN_DELAY_SECS` | optional, pool only, seconds before a new agent or vault takes effect, from 7 to 30 days, default 7 days |
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
there and one share-note key per tier; creating and holding those keys for the agent is not built yet. Lending vaults are refused.
A new vault or agent takes effect only after the admin delay, and anyone can leave in the meantime. Depositors pay the pool through
its `deposit` method, at least 0.1 NEAR; a plain transfer is never credited to anyone. A holder can move notes to another listed
vault without an exit (`switch_vault`, submitted by the agent); the agent then moves the funds inside the pool with `settle_switch`.
Nothing new to configure.

## Run the signer

```
cargo run -p ona-signer -- init-keys signer-keys.bin 8
```

This creates the mint keys in a new private file, and prints the public keys to give to the contract at deployment. Each deployment
needs its own keys. To issue tokens:

| Variable | Value |
|---|---|
| `ONA_RPC_URL` | NEAR RPC endpoint |
| `ONA_MINT` | account of the deployed contract |
| `ONA_SIGNER_ACCOUNT` | account named as signer in the contract |
| `ONA_SIGNER_ACCOUNT_KEY_FILE` | file holding `ed25519:<base58>`, readable by its owner only |
| `ONA_SIGNER_KEYS_FILE` | the file from `init-keys` |
| `ONA_SIGNER_STATE_FILE` | where the signer records its progress; must survive restarts |

```
cargo run -p ona-signer -- run
```

It refuses to start if its keys are not the ones the contract verifies against.

## Run the relay

```
cargo run -p ona-server --bin ona-relay -- init-key relay-request-keys.bin
```

To serve, on `127.0.0.1` only:

| Variable | Value |
|---|---|
| `ONA_RPC_URL` | NEAR RPC endpoint |
| `ONA_MINT` | account of the deployed contract |
| `ONA_NETWORK` | network name used when the contract was created |
| `ONA_RELAY_ACCOUNT` | account named as relay in the contract |
| `ONA_RELAY_ACCOUNT_KEY_FILE` | file holding `ed25519:<base58>`, readable by its owner only |
| `ONA_RELAY_REQUEST_KEY_FILE` | the file from `init-key` |
| `ONA_RELAY_STORE_FILE` | where the relay records exchanges; must survive restarts |
| `ONA_MODELS` | allowed models, separated by commas |
| `NEAR_AI_CLOUD_API_KEY` | NEAR AI key. Set it with `read -s`, never in a file |
| `ONA_RELAY_PORT` | optional, default 8787 |
| `ONA_FLUSH_SECS` | optional, seconds between batches of claims, default 60 |
| `ONA_TOKENS_PER_CREDIT` | optional, default 100 |
| `ONA_MAX_TOKENS` | optional, most tokens per reply, default 512 |

```
cargo run -p ona-server --bin ona-relay -- run
```

It serves 8 connections at a time and keeps 32 waiting; beyond that it answers 503. Attestation and signature routes are limited to 600 calls per
minute across all clients. If the store reports a write error, every further write is refused until the relay is restarted.

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
