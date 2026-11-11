# ONA build spec v1 (2026-11-10)

**Status: draft, not reviewed by a cryptographer. The contract must not hold real funds.**

## Layout
Under `crates/`: `ona-token` crypto and token format · `ona-mint` NEAR contract · `ona-registry` NEAR contract · `ona-signer` issuing
loop · `ona-server` relay · `ona-wallet` encrypted wallet file · `ona-core` local mission core and CLI · `ona-sandbox` deployment and
gas harness · `ona-anchor` journal anchoring aggregator.

## Curve choice
Message and signature in **G1**, public key in **G2**. 48-byte tokens. All points reach `pairing_check`, which rejects
non-subgroup points on NEAR.

## Measured gas
`crates/ona-sandbox` on near-sandbox 2.13.4, 2026-11-10. Tgas burnt by the whole transaction, including its receipts.

| Operation | Tgas |
|---|---|
| deploy + `new` (4 tiers, 229 KB wasm) | 62.8 |
| `deposit` x1 / x64 | 3.0 / 4.4 |
| `lock` | 1.9 to 2.4 |
| `issue` x1 / x8 / x32 / x64 | 9.5 / 57.6 / 222.5 / 442.5 |
| `redeem` | 19.0 |
| `spend`, no change / one change | 13.4 / 14.1 |
| `relay_claim` x1 / x8 / x32 | 10.6 / 68.0 / 264.6 |
| `halt` | 1.7 |

`issue` costs about 6.9 Tgas per token, and `relay_claim` about 8.3. These runs attached 1000 Tgas; the limit on testnet is not verified.

The same run confirmed: the deployed account has no access key, a transfer to a missing account comes back to the token's own implicit
account, an outsider cannot call the payout callback, and the reserve stayed solvent after every step. On the same node, the real signer
loop locked and issued a deposit, and the real relay claimed a credit, returned request tokens and refused one used twice.

## Token
| Field | Size | Role |
|---|---|---|
| `denom_id` | 1 | tier 0..=7, selects the key and is part of the signed message |
| `pk` | 32 | owner ed25519 public key |
| `nonce` | 32 | random |
| `sig` | 48 | compressed G1 |

- Message `m = denom_id || pk || nonce` (65 bytes).
- DST: `ONA-MINT-V1:<network>:<contract_account>:BLS12381G1_XMD:SHA-256_SSWU_RO_`.
- Nullifier: `sha256("ONA-NF-V1" || denom_id || pk || nonce)`.
- Blinding: `H = hash_to_g1(m, DST)`, `B = r*H`, signer returns `S' = sk*B`, wallet unblinds `S = r^-1 * S'`, then checks
  `e(S, G2) == e(H, pk_G2)`. `r` uniform and never derived from a seed.
- **Each deployment must have its own keys.** The signer is blind and cannot see the DST of a blinded point, so the DST does
  not protect against a key shared between two deployments.

## Owner signatures (ed25519 over a SHA-256 digest)
Each message starts with its own domain string, so a signature for one action cannot serve for another.
- `redeem_digest = H("ONA-REDEEM-V1" || H(contract) || H(submitter) || nf)`
- `spend_digest = H("ONA-SPEND-V2" || H(contract) || H(submitter) || denom || nf || H(to) || amount_le || fee_le || count_le || (denom || B)*)`
- `claim_digest = H("ONA-CLAIM-V1" || H(mint) || H(relay) || nf)`

## `ona-mint` contract
Tested on the mocked NEAR VM, which runs the real BLS12-381 and ed25519 host functions, with tokens produced by `ona-token`.

State: denoms (value, pk, caps), counters per denom (deposited, issued, redeemed, refunded, hourly window), pending deposits,
nullifier set, signer, relay, guardian, halted.

| Method | Access | Effect | Must refuse |
|---|---|---|---|
| `new` | once | validates keys | invalid or duplicate keys |
| `deposit(denom, blinded[])` | anyone, payable | records pending, prepaid storage and fee outside the reserve | halted; n not in {1,2,4..64}; over circulation cap; bad length |
| `lock(id)` | signer | blocks `refund` for 24 h, before any signature is published | halted; not signer; deadline passed; already locked |
| `issue(id, sigs[])` | signer | per-token verification, issued += n. Allowed after `halt` for locked records | not locked; lock expired; not signer; one bad signature fails all |
| `refund(id)` | anyone after deadline, or after lock expiry if locked | returns the deposit | too early; issued |
| `redeem(token, owner_sig)` | anyone named by the owner | verifies, marks spent, pays `hex(pk)` | forged; spent; bad owner sig; redeemed+1 > issued; bucket empty |
| `spend(token, owner_sig, to, amount, fee, change[])` | anyone named by the owner | verifies, marks spent, pays `to`, records `change` as pending with refund to `hex(pk)`. A failed transfer goes to `hex(pk)` by callback | forged; spent; bad owner sig; `amount + fee + sum(change) != value`; fee below the change cost; change while halted; bucket empty |
| `relay_claim(items[])` | relay | as redeem + owner sig; bad item returns false and continues; dedupes within the call | not relay; too many |
| `halt()` | guardian | stops deposit, lock and new change | not guardian |

**Invariant I1, checked after every method in tests:** `balance - storage_cost - liabilities` is positive and never decreases, with
`liabilities = sum((issued - redeemed) * (value + storage_per_token)) + pending_held + signer_fees`.

### Issuance rule
Blinded signatures are public as soon as an `issue` transaction is sent, even if it fails. The signer therefore locks first, reads
the lock back, and only then publishes. It starts no first broadcast within an hour of the lock's expiry. It records each broadcast
on disk before sending, and keeps retrying a broadcast record until the lock ends, across restarts.

**Remaining risk:** a signer that publishes, fails, and stays down or keeps failing until the lock ends leaves a window where the
depositor can combine a refund with the public signature. `issue` of 64 tokens must be sent with enough gas; the amount is not measured yet.

### Known limits, not fixed
- Key theft lets the thief drain the reserve at the speed of the hourly bucket. No key rotation by design.
- An attacker holding tokens can use up the hourly bucket of a tier at the start of each hour, freezing exits for that tier.
- Refundable deposits of unsignable points can occupy the circulation cap for free.
- `redeem` and refunds of change pay the owner's implicit account in the clear.

## `ona-registry`
`anchor(root, count)` by the aggregator. `propose(action)` then `confirm(id)` by the other owner, for `Publish`, `Revoke`,
`SetIncident`, `SetAggregator`. Published values are append-only with a 7-day delay checked at confirmation.

## App skeleton
Local only, model faked and every fake response labelled `mode: mock`. Mission state machine with a plan frozen before any web
read; closed-schema reader output; payment gate with allowlisted templates, recipient list and amount cap (code, not model);
hash-chained journal with one-byte tamper detection; exposure report built from the journal; `dispatch(json) -> json`; CLI
(`ona demo`). `Journal::seal` produces the auditor form: XChaCha20-Poly1305 per entry, keys from HKDF, padded to 512-byte blocks,
chain verifiable without a key, one entry can be disclosed alone. The master key is sealed to the auditor's public key by
`auditor::seal_master_key` (see below); nothing in the mission calls it yet.

## Journal anchoring (`crates/ona-core/src/checkpoint.rs`, `crates/ona-anchor`)
- Leaf of a checkpoint: `SHA-256(0x00 || "ona/leaf/v1" || salt || journal head)`, with a new random salt for each checkpoint, so two
  leaves of one mission cannot be linked. Nodes: `SHA-256(0x01 || left || right)`, as in RFC 9162.
- The tree always has depth 10 (1024 leaves). Real leaves sit at random positions and the rest are random filler leaves, so a root is
  always 32 bytes and an inclusion proof always 2 + 10 × 32 bytes (index, then siblings), whatever the batch size.
- `ona-anchor` collects leaves, refuses duplicates and more than 1024 per batch, anchors one tree per hour even when empty, and returns
  the proofs. It keeps nothing once a batch is anchored. A refused anchor keeps the leaves for the next attempt with a new tree.
- `anchor(root, count)` is always sent with `count = 1024`: the real number would reveal how busy the hour was. The contract field
  therefore says nothing about activity.
- Not built: a program that receives leaves and delivers proofs over the network, and the agent side that submits checkpoints. Before
  such a program exists it needs a per-client limit, or one client can fill every batch. Today only the submitter of a leaf can notice
  that it was left out.

## Auditor key (`crates/ona-core/src/auditor.rs`)
The journal's 32-byte master key is sealed to the auditor's X25519 public key: ephemeral X25519 key, HKDF-SHA256 bound to both public
keys, XChaCha20-Poly1305. Format: version (1) · ephemeral public key (32) · nonce (24) · ciphertext and tag (48). The caller's copy
is wiped after a successful seal and kept after a failed one. Copies made elsewhere in memory are not reached.

## Chat retention (`crates/ona-core/src/vault.rs`)
Local history only if the user chooses it, otherwise automatic deletion after 24 hours. Chat results stay encrypted on the device with one key per chat, 24 hours from the first save by default; saving again does not
extend it. Expiry destroys the key, then the file, and a read is refused even if the purge has not run. `keep` is the user's choice
for one chat, `forget` deletes any chat at once. No chat result ever goes on chain. Keys are in a private local file until the
keychain is wired in. What the user copies or backs up is their own choice and must be stated in the app.

## Encrypted model client (`crates/ona-core/src/e2ee.rs`)
NEAR AI encryption version 3 through the relay, written from the public `nearai/inference-proxy` sources and tested only against a simulated
enclave. Each encrypted request field is bound to the reply key, so a relay replacing `X-Client-Pub-Key` makes the request undecryptable. This
fixes the reply-key attack only if the NEAR AI gateway accepts version 3, which is **not verified**. Version 2 needs an explicit setting, and a
failed call never falls back to it. Version 3 does not bind a reply to one precise request, a replay carrying the original reply key is still
processed, and the relay still sees sizes and counters. Each request gets a new client key and a fresh attestation nonce. A reply counts only
if the signature comes from the attested model key (`provider_tee`) and covers the exact bytes sent and received. Every request carries
`max_tokens`, and a per-client budget stops calls before they spend. The relay sees the usage counters, so pricing must be flat per
request. TDX and NVIDIA quotes are not verified yet.

`crates/ona-core/src/quote.rs` checks a model attestation, not yet called by the client. **It is worth nothing until the Intel signature
check is implemented:** that check (meant for `dcap-qvl`) and NVIDIA's service are traits with no implementation, so nothing passes outside
tests, and without the signature anyone can write a quote holding any value. With it, a quote passes only if MRTD and RTMR0 to RTMR2 are
on the caller's list, the event log replays to RTMR3, its `os-image-hash` and `compose-hash` events name a listed image and the hash of the
reported `app_compose`, `report_data = signing_address || nonce` (32 + 32 bytes), `mr_config_id = 0x01 || compose hash || 15 zero bytes`,
the enclave is not in debug mode, and the deployment hash is listed. `mr_config_id` alone proves nothing: the host chooses it. **The GPU
evidence is not bound to the TDX quote:** its nonce shows it is fresh, but a relay can copy a genuine payload from another machine.
Formats were checked on one real report (2026-11-10) that NEAR AI's official verifier accepted, not against the verifier's source. RTMR3
events carry no digest in the log: each is `sha384(event_type as u32 little-endian || ":" || event || ":" || payload)`. The listed values
in `observed_2026_11_10` were seen in that report, not published by NEAR AI, and change with each image update.

## Wallet (`crates/ona-wallet`)
Append-only encrypted file, synced before the action it protects: token secrets before the deposit, spending mark before a spend.
Removing lines from the end is not detected. Key storage in the operating system's keychain is not implemented.

## Relay (`crates/ona-server`)
HTTP/1.1 front (`server/src/http.rs`) and a fake relay for front ends (`ona-mock-relay [port]`, localhost only, with a free-credit
route that exists only in that binary). `NearRelayChain` connects it to the contract. `gateway.rs` passes encrypted NEAR AI calls byte for byte: it forwards an allowlist of headers and
requires a one-use request token per chat. Before the token is spent, a chat must have exactly `model`, `messages`, `stream` and `max_tokens`, no duplicated
JSON key, one user message in hexadecimal, the encryption headers, a listed model and a body of at most 64 KiB. Attestation and signature routes accept only
the exact forms used by the client, under one limit per minute for all clients. Service errors keep their status and lose their text. A reply over
budget is withheld, as a last resort since the call is already paid. `ona-relay` is the program that runs all this. It has not run yet. No padded batches or enclave yet.

The relay is not trusted with content: with encryption version 2 a dishonest relay can replace the client key and read the reply. Version 3 closes this
only if the NEAR AI gateway accepts it, which is not verified.

Each connection has one deadline to send its whole request and one to receive the whole reply. Connections are served by a fixed pool with a bounded queue,
and a full queue answers 503. Chain and model calls run without holding the relay state.

Credit exchange checks the credit and its owner signature before anything else, writes state durably before each irreversible step and signs only after
the chain confirms. A `false` from `relay_claim` is read again in a final block: claimed by this relay gives the tokens, spent by someone else refuses, and
anything else, such as the hourly limit, stays pending. Request tokens are recorded as used before the model call, and returned durably only when the
service refused the connection or answered 401, 402 or 429. The journal cuts a last line without a newline at startup, stops after a failed write until
restarted, and is rewritten with one line per credit and per used token.
