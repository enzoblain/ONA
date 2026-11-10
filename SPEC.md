# ONA build spec v1 (2026-11-10)

**Status: draft, not reviewed by a cryptographer. The contract must not hold real funds.**

## Layout
Under `crates/`: `ona-token` crypto and token format · `ona-mint` NEAR contract · `ona-registry` NEAR contract · `ona-signer` issuing
loop · `ona-server` relay · `ona-wallet` encrypted wallet file · `ona-core` local mission core and CLI · `ona-sandbox` deployment and
gas harness.

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
chain verifiable without a key, one entry can be disclosed alone. Sealing the master key to the auditor's public key is not implemented.

## Chat retention (`crates/ona-core/src/vault.rs`)
Local history only if the user chooses it, otherwise automatic deletion after 24 hours. Chat results stay encrypted on the device with one key per chat, 24 hours from the first save by default; saving again does not
extend it. Expiry destroys the key, then the file, and a read is refused even if the purge has not run. `keep` is the user's choice
for one chat, `forget` deletes any chat at once. No chat result ever goes on chain. Keys are in a private local file until the
keychain is wired in. What the user copies or backs up is their own choice and must be stated in the app.

## Encrypted model client (`crates/ona-core/src/e2ee.rs`)
NEAR AI encryption version 2 through the relay. Each request gets a new client key and a fresh attestation nonce. A reply counts only
if the signature comes from the attested model key (`provider_tee`) and covers the exact bytes sent and received. Every request carries
`max_tokens`, and a per-client budget stops calls before they spend. The relay sees the usage counters, so pricing must be flat per
request. TDX and NVIDIA quotes are not verified yet.

## Wallet (`crates/ona-wallet`)
Append-only encrypted file, synced before the action it protects: token secrets before the deposit, spending mark before a spend.
Removing lines from the end is not detected. Key storage in the operating system's keychain is not implemented.

## Relay (`crates/ona-server`)
HTTP/1.1 front (`server/src/http.rs`) and a fake relay for front ends (`ona-mock-relay [port]`, localhost only, with a free-credit
route that exists only in that binary). `NearRelayChain` connects it to the contract. No padded batches, real model, Tor or enclave yet. Credit exchange writes state durably before each
irreversible step and signs only after the chain confirms. Request tokens are recorded as used before the model call. A reply
over the per-request budget is withheld.
