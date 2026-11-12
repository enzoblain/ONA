# ONA build spec v1 (2026-11-10)

**Status: draft, not reviewed by a cryptographer. The contract must not hold real funds.**

## Layout
Under `crates/`: `ona-token` crypto and token format · `ona-mint` NEAR contract · `ona-registry` NEAR contract · `ona-signer` issuing
loop · `ona-server` relay · `ona-wallet` encrypted wallet file · `ona-core` local mission core and CLI · `ona-sandbox` deployment and
gas harness · `ona-anchor` journal anchoring aggregator · `ona-pool` NEAR contract holding the funds the agent places · `ona-near` NEAR
RPC client · `ona-deploy` deployment tool · `ona-crowd` crowd simulator · `ona-agent` the pool's agent.

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

`issue` costs about 6.9 Tgas per token, and `relay_claim` about 8.3. These runs attached 1000 Tgas. The contract now accepts at most
32 tokens per deposit and 28 items per `relay_claim`, so the signer's budget formula (10 + 8 per token, 266 Tgas for 32) and the
relay's (10 + 10 per item, 290 Tgas for 28) stay under 300 Tgas; whether the new code fits these budgets is not measured. `lock` now
updates one counter per token, so its cost grows with the token count (not measured; the signer attaches a fixed 10 Tgas). The 300 Tgas is the `max_total_prepaid_gas` of protocol versions before 83 in
`near-parameters` 0.38.0 (version 83 raises it to 1 PGas). Which protocol version runs on testnet is not verified; it can be read
from the network's protocol config (RPC `EXPERIMENTAL_protocol_config`, not verified here). The table was measured before the
2026-11-11 changes (lock accounting, expiry, duplicate checks, signatures in the `issue` event) and has not been measured again.

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
- Secrets held by `ona-token` (mint keys, blinding factors, key generation and blinding buffers, the pending token's nonce and
  seed) are wiped with volatile writes when dropped. `SecretKey::to_secret` and `PendingToken::to_secret_vec` return buffers wiped
  on drop; the older `to_bytes` and `to_secret_bytes` return copies the caller must wipe. Copies made elsewhere in memory (moves,
  registers, swap) are not reached.
- **Each deployment must have its own keys.** The signer is blind and cannot see the DST of a blinded point, so the DST does
  not protect against a key shared between two deployments.

## Owner signatures (ed25519 over a SHA-256 digest)
Each message starts with its own domain string, so a signature for one action cannot serve for another. Each carries `expires_at`,
the last block timestamp in nanoseconds (u64, little-endian) at which the contract accepts it, passed in clear next to the signature.
The contract refuses an `expires_at` already passed, or more than `MAX_SIGNATURE_VALIDITY_NS` (7 days) after the block that executes
it, so no signature can be made valid for ever.
- `redeem_digest_until = H("ONA-REDEEM-V2" || H(contract) || H(submitter) || nf || expires_at_le)`
- `spend_digest_until = H("ONA-SPEND-V3" || H(contract) || H(submitter) || denom || nf || H(to) || amount_le || fee_le || count_le || (denom || B)* || expires_at_le)`
- `claim_digest_until = H("ONA-CLAIM-V2" || H(mint) || H(relay) || nf || expires_at_le)`
- `exchange_digest = H("ONA-EXCHANGE-V1" || H(mint) || H(relay) || nf || H(B_1 || ... || B_n))`, with the raw 48-byte blinded points in
  request order. Checked by the relay only (`exchange_sig`), never by the contract: it fixes the points an exchange pays for.

The earlier formats (`ONA-REDEEM-V1`, `ONA-SPEND-V2`, `ONA-CLAIM-V1`, functions without `_until`) remain in `ona-token` for
existing callers but are no longer accepted by `ona-mint`. Owner keys of small order are refused by the contract (the host's
`ed25519_verify` is not strict in `near-vm-runner` 0.38.0; the deployed host version is not verified) and by `verify_digest`, which
uses `verify_strict`. `is_weak_owner_key` lets a wallet or relay check a key before use.

## `ona-mint` contract
Tested on the mocked NEAR VM, which runs the real BLS12-381 and ed25519 host functions, with tokens produced by `ona-token`.

State: denoms (value, pk, caps), counters per denom (deposited, issued, redeemed, refunded, a redemption bucket for `redeem` and
`spend`, a separate one for `relay_claim`), pending deposits, nullifier set, signer, relay, guardian, halted.

| Method | Access | Effect | Must refuse |
|---|---|---|---|
| `new` | once | validates keys, roles and tiers | invalid or duplicate keys; a key equal to another's negation; tier values not strictly increasing; signer, relay and guardian not pairwise distinct or equal to the mint; network not 1 to 32 characters of `a-z 0-9 - _` |
| `deposit(denom, blinded[])` | anyone, payable | records pending, prepaid storage and fee outside the reserve | halted; n not in {1,2,4..32}; the same point twice; over circulation cap; bad length |
| `lock(id)` | signer | counts the tokens as issued (issued += n) and blocks `refund` for good, before any signature is published | halted; not signer; deadline passed; already locked |
| `unlock(id)` | signer | reverses `lock` (issued -= n); the record refunds at its deadline. For records whose signatures were never broadcast | not signer; not locked; fewer live tokens in a tier than the record removes |
| `issue(id, sigs[])` | signer | per-token verification; the event carries the blinded signatures. Allowed at any time after `lock`, also after `halt` | not locked; not signer; one bad signature fails all |
| `refund(id)` | anyone after the deadline, unlocked records only | returns the deposit | too early; locked; issued |
| `redeem(token, owner_sig, expires_at)` | anyone named by the owner | verifies, marks spent, pays `hex(pk)` | forged; spent; bad, expired or small-order owner sig; redeemed+1 > issued; bucket empty |
| `spend(token, owner_sig, to, amount, fee, change[], expires_at)` | anyone named by the owner | verifies, marks spent, pays `to`, records `change` as pending with refund to `hex(pk)`. A failed transfer goes to `hex(pk)` by callback | forged; spent; bad, expired or small-order owner sig; `amount + fee + sum(change) != value`; the same change point twice; fee below the change cost; change while halted; bucket empty |
| `relay_claim(items[])` | relay | as redeem, each item with its own `expires_at`; bad item returns false and continues; dedupes within the call; uses the relay's own bucket | not relay; more than 28 items |
| `halt()` | guardian | stops `deposit`, `lock` and change in `spend` | not guardian |
| `pending_scan(from, limit)` | view | live records among at most 256 ids from `from` (`limit` from 1 to 64, 0 counts as 1), and the id to continue from. `pending_deposits` returns the same records without the cursor | |

**Storage layout.** The 2026-11-11 version changed the stored counters (two sliding buckets replace the hourly window) and the
meaning of `locked_until` (`u64::MAX` once locked, no expiry). There is no migration and no upgrade method: a contract deployed with
the earlier code must be redeployed, not upgraded.

**Duplicate blinded points** are refused only within one record (one deposit, or the change of one spend). The same point in two
different records is not detected: its second copy would get the same signature, and only one token could be spent; the loss falls
on the depositor who sent it twice.

**What `halt` does not stop:** `redeem`, `spend` without change, `relay_claim`, `refund`, `unlock`, and `issue` of a record already
locked. It does not lower the redemption limits: a thief holding the signer key keeps redeeming at the buckets' pace after a halt.

**Redemption limit.** Each tier has `hourly_redeem_cap`. A bucket gains one unit per redemption and drains at `cap` units per hour,
continuously; a redemption that would take it above `cap` is refused. So at most `cap` redemptions at once and at most
`cap + cap × t / 1 h` over any period `t` (below 2 × cap over any hour), with no reset on the hour. `redeem` and `spend` share one
bucket; `relay_claim` has its own, so holders emptying the public bucket do not stop the relay. Together the two paths can therefore
pay out up to twice the cap of a tier.

**Invariant I1, checked after every method in tests:** `balance - storage_cost - liabilities` is positive and never decreases, with
`liabilities = sum((issued - redeemed) * (value + storage_per_token)) + pending_held + signer_fees`.

### Issuance rule
Blinded signatures are public as soon as an `issue` transaction is sent, even if it fails. The signer therefore locks first, reads
the lock back, and only then publishes. `lock` is the accounting commitment: it counts the tokens as issued, and a locked record can
never be refunded, so public signatures can never be combined with a refund. A lock does not expire (`locked_until` reads
`18446744073709551615` once locked) and `issue` can land at any time after it. The signer records each broadcast on disk before
sending. It may `unlock` only a record it never broadcast (for example one it cannot sign); `unlock` is refused if a tier has fewer
live tokens than the record removes. Remaining trust: a signer that broadcasts and then calls `unlock` anyway brings back the old
risk (refund plus public signatures); a signer that locks and never issues nor unlocks leaves the deposit in the contract for good,
counted as issued tokens. Both cost the depositor or rest on the signer, never on other holders as long as the signer is honest.

**The signer (`crates/ona-signer`).** It retries `issue` of a broadcast record without time limit, unlocks a locked record it never
broadcast and cannot sign, and stops if a broadcast record can no longer be signed. Its state file names the mint and its keys, is
readable by its owner only and held by one process; a new state file is refused while the contract holds locked deposits (every
record id is scanned), and a file left empty by a crash counts as new. Before an `issue` whose earlier attempt had an unknown outcome,
it asks the node for that transaction's status and sends nothing if it landed.

**Trust in the RPC.** The signer signs what the chain shows, so a lying RPC could obtain signatures without a deposit. Each pass reads
deposits and keys on two endpoints (`ONA_RPC_URL`, `ONA_RPC_URL_2`) at one final block pinned for the whole pass, the lower of the two
final blocks, checked by height on the other endpoint. The two final heights may differ by at most 20 blocks, and the block may not be
below the highest one already used, which the state file keeps (written every 600 blocks and before each broadcast or unlock), so one
endpoint cannot impose an older view of the chain. Any difference stops the pass. Both endpoints must report the expected chain id.
URLs must be `https`, or `http` to the machine itself; redirects and proxy variables are refused. Two endpoints that lie together are
not detected; a light client or an own node would be needed for that. The RPC formats used are from the NEAR RPC documentation and
**not verified** against a live node here.

**Order.** Each pass reads up to 8 `pending_scan` pages from its cursor (at most 512 deposits and 2048 ids; what lies beyond waits for
the next pass), locks first, going round the depositors so that a flood from one account delays the others by one turn each, then
issues. Several accounts get several turns, so a flood spread over many accounts can still delay locks past the one-hour deadline;
those deposits are then refunded, nothing is lost. A pass starts no new record after 10 minutes. The cursor moves to the first record
still to retry, or to where the scan stopped, so runs of finished ids do not stop issuance. `lock` and `unlock` get 10 + 2 Tgas per
token and `issue` 10 + 8 Tgas per token (266 for 32); the `lock` budget is not measured.

### What links a deposit to a spend
Blinding hides which deposit a token came from, and BLS signatures are unique, so the signer cannot tag a token. Everything else is
public on chain:
- **Anonymity set.** `get_denom` publishes `issued` and `redeemed` per tier. A spend hides among at most `issued - redeemed` live
  tokens of its tier, which `circulation_cap` also bounds. One live token in a tier means a certain link.
- **Timing and count.** A deposit of `n` tokens of tier `d` by an account, followed by `n` spends of tier `d` soon after, links
  without any cryptography. Amounts split over several tiers give simultaneous deposits from the same account.
- **Amount and recipient.** `spend` publishes `to`, `amount`, `fee` and the tiers of the change; `redeem` pays `hex(pk)`. A
  withdrawal of an amount close to a deposit can be guessed.
- **Change chains.** A change record is public (`is_change`, depositor `hex(pk)` of the spent token). In a sparsely used tier the
  next spend of that tier is likely the same user.
- **Submitting account.** `spend` and `redeem` bind the signature to the calling account. Submitting with the account that
  deposited links the two directly. No production client calls `spend` yet, so the submission path is not settled.
- **Fee.** `fee` is free; an unusual value identifies the software or the relay.
- **Fetching signatures.** The blinded signatures are in the `issue` event; whoever serves that read learns which deposit a client
  is interested in, unless the read goes through Tor.
Nothing in the contract enforces a minimum set size, a delay or a fixed fee; that is left to the client and is not built.

### Known limits, not fixed
- Key theft lets the thief drain the reserve at the speed of the buckets (redeem/spend plus relay, if the relay accepts the stolen
  tokens). No key rotation and no guardian brake on the limits by design.
- An attacker holding tokens can keep the public bucket of a tier empty, slowing `redeem` and `spend` of that tier; the relay's
  bucket is separate.
- Refundable deposits of unsignable points can occupy the circulation cap for free; valid deposits sent faster than the signer can
  process them push honest deposits past their deadline (not measured).
- `redeem` and refunds of change pay the owner's implicit account in the clear.
- Plain transfers (`redeem`, `refund`, signer fees, relay claims, fee to the submitter) have no callback: if the paid account was
  deleted meanwhile, the amount comes back to the contract and stays there, unreachable. Solvency is unaffected. Only `spend`'s
  payment has a callback.
- Tier safety rests on independent keys. `new` refuses identical keys and a key with its negation, but cannot detect `k × pk` for a
  known `k`: keys must be generated separately for each tier, never derived from one another.

## `ona-registry`
Tested on the mocked NEAR VM only; the wasm build of this version is not verified.
- `anchor(root)` by the aggregator, at most once every 30 minutes. The anchor stores `seq`, `root` and the block timestamp.
- `propose(action)`, then `confirm(id, action)` by the other owner, restating the exact action (`get_proposal(id)` shows it).
  Actions: `Publish`, `Revoke`, `SetIncident`, `SetAggregator`, `ChangeOwner`, `Restore`. The action is checked again against
  the current state when confirmed. A proposal expires after 30 days, only its proposer can cancel it, and each owner may have
  at most 4 pending. A replaced owner's pending proposals are removed.
- `emergency(action)` by one owner alone: `Revoke`, or `SetIncident` with a higher level. Nothing else. A value revoked this way
  can be brought back by both owners with `Restore`, or made final by both owners with `Revoke`; a value revoked by both owners
  cannot be restored.
- `propose_takeover(new)`: one owner proposes to replace the other, confirms it alone after 30 days (it expires after 60), and
  the owner being replaced can `veto` it until then. A lost key is thus recoverable. The same path works for a thief: **someone
  holding a stolen copy of one owner's key replaces the other owner if that owner does not veto within 30 days.** Owners must
  watch for takeover proposals. A stolen copy can also veto a takeover aimed at it, and then only a new registry helps.
- Lowering the incident level, changing the aggregator, replacing an owner or restoring a value can be confirmed only 7 days
  after the proposal. The aggregator can never be an owner.
- Published values are append-only, take effect at least 7 days and at most 90 days after confirmation, and a publication is
  refused while another one on the same topic is still waiting. `active` returns the newest value in force; if it was revoked
  the topic has no value: an older value never comes back by itself. A value revoked before its date is skipped, and a revoked
  value can never be published again. An older value that was never revoked can be published again, as a new entry with its own
  notice. Topics: lowercase letters, digits, `-` and `_`.
- `anchor` and `propose` are payable: the caller pays the storage it adds and gets the excess back. The price per byte is the
  network's (not verified here); `ona-anchor` attaches 0.01 NEAR per anchor.
- Proposals that have expired no longer count against the limit of 4. No client reads `active` or `incident_level` yet.

## `ona-pool` (`crates/ona-pool`)
The account that holds the funds the agent places. Never deployed, tested on the mocked NEAR VM only, with notes made by
`ona-token`. No staking pool has been called for real. Gas is not measured.

- **Roles.** Created by `ona-deploy pool` with no access key. The `guardian` lists vaults, freezes them, sets the agent account and the
  fee. The `agent` is an account set by the guardian. Checking that the agent's key lives in an attested enclave is done outside the
  contract and is not built. A new agent (`set_agent`), a new vault (`add_vault`) or a new fee (`set_fee_bps`) is announced and takes
  effect only after the admin delay (set at creation, from 7 to 30 days, 7 by default: meant to be at least as long as a staking pool
  takes to return unstaked funds, which is not verified). Meanwhile the current agent keeps working but cannot place nor enter, and
  the escape is open to everyone. Freezing a vault takes effect at once: it stops entries and placements, nothing else.
- **Two compartments.** Money inside the pool is either **cash**, which backs blind cash notes of fixed value and belongs to no vault,
  or in a **vault**, which backs that vault's share notes. Deposits become cash (`issue_cash`), cash enters a vault (`enter`), shares
  leave a vault as cash (`leave`), and exits pay cash notes (`pay_exit`). Switching vaults is a `leave` then an `enter`. The cash is
  always fully backed: it holds at least the value of every cash note issued and not paid (`get_cash`: `liquid` ≥ `outstanding`).
- **Vaults on a list.** Each vault has an adapter type and a target account. `staking` calls only `deposit_and_stake` (with the amount
  attached), `unstake {amount}`, `withdraw {amount}` and the views `get_account_total_balance`, `get_account_staked_balance` and
  `get_account_unstaked_balance` (each `{account_id}`), as named in the standard NEAR staking pool (`near/core-contracts`,
  `staking-pool`), from memory: the names and the behaviour below are **not verified** against its source, and no staking pool has run. `lending` cannot be added: no lending interface has
  been checked against its source, so its adapter is not implemented. The guardian also records the SHA-256 of the code it checked
  at the target, shown by `get_vault`; a contract cannot read another account's code, so the pool does not verify it. A target can
  serve one vault only. Each vault's hourly cap must cover two of its largest notes at the initial price. `get_vault` publishes each
  tier's key uncompressed (`pk_raw`), and `orphan` (see Share price), without which a wallet cannot compute the entry price
  the contract applies. A vault runs one call at a time, numbered: only the callback of the call in progress frees the
  vault (`on_place`, `on_unstake`, `on_withdraw`, `on_sync`, and `on_staked_read` / `on_unstaked_read` which chain the forced calls
  below), and a call whose callback never returns stops blocking after one hour. Gas for those calls (50 Tgas, callback 20 Tgas, a
  reading callback that chains a call 80 Tgas) is not measured.
- **Unstaking and withdrawing.** Whether each `unstake` on the standard staking pool restarts the lock on everything already unstaked
  is **not verified**. The agent chooses the amount while the vault is not open (see Escape). Once it is open, anyone may call, the
  agent included, and the contract fixes the amount: everything placed if the agent has been silent for the escape delay or the
  vault's list has stayed full for that delay (any note may then leave), otherwise what the vault's payable requests need beyond its
  liquid funds. `placed` (the total balance) counts staked and already unstaked funds together, and the staking pool is expected to
  refuse an `unstake` above what is staked and a `withdraw` above what is unstaked (not verified). So a call whose amount the
  contract fixes first reads the target's balances and asks for at most what is there: a forced `withdraw` reads
  `get_account_unstaked_balance`; a forced `unstake` reads both `get_account_unstaked_balance` and `get_account_staked_balance`,
  asks for at most the staked part, and asks for nothing while unstaked funds are still waiting there (event `unstake_waits`): each
  `unstake` is expected to push back the release of everything already unstaked (not verified), so a saboteur repeating a forced
  `unstake` every 3 days could otherwise keep those funds locked; the `withdraw` comes first. An `unstake` of 1 yocto by the agent, or
  share rounding at the staking pool, cannot make a forced call fail. A failed reading frees the vault and starts no interval. How
  long the staking pool really keeps unstaked funds locked (a number of epochs, not verified), and whether a new `unstake` restarts
  that wait, are to be measured on a local node; the tests use a stand-in of 36 hours. At most one successful `unstake` per vault every 3 days (a design
  margin) of each kind: the agent's own calls and the calls whose amount the contract fixes have separate intervals, so an
  `unstake` by the agent just before a request is overdue cannot hold back the one the contract fixes. A failed call does not count
  (`on_unstake` reads the result). Someone other than the agent can `withdraw` at most once an
  hour per vault, and `sync` only when the last reading is older than an hour, so others cannot keep a vault busy.
- **Notes.** Blind BLS notes as in `ona-mint`, message `tier || pk || nonce`, one key per tier (a key serves one tier of one vault or of
  the cash, never two). Share notes: tag `ONA-POOL-V1:<network>:<contract>:<vault>:BLS12381G1_XMD:SHA-256_SSWU_RO_`, nullifier
  `SHA-256("ONA-POOL-NF-V1" || vault (u32 LE) || tier || pk || nonce)`; a tier carries a fixed number of shares. Cash notes: tag
  `ONA-POOL-CASH-V1:<network>:<contract>:BLS12381G1_XMD:SHA-256_SSWU_RO_`, nullifier
  `SHA-256("ONA-POOL-CASH-NF-V1" || tier || pk || nonce)`; a tier is worth a fixed amount, set at creation with its key, each worth
  more than the exit and storage fees. An owner key serves one note only: a key already used by a spent note is refused. Owner keys
  of small order (the 8 points and their non-canonical encodings, `WEAK_KEYS`) are refused: with one, a signature can be made for any
  message.
- **Share price.** `(liquid + placed − fee owed − orphan) / shares`, rounded down to value a note leaving and up to price one entering;
  10^-6 NEAR per share in a vault with no share. `placed` is set by `sync`, which reads the target's own balance for the pool. `enter`,
  `leave` and share-note exits use a price only if the vault was read within the hour or holds nothing at its target. When a vault's
  last shares are gone, what is left there (unread rewards, rounding) is set aside as owned by nobody (`orphan`), so the next entrant
  does not take it. There are no virtual shares. A staking pool credits rewards by epoch (epoch length not verified here), so the
  balance a sync reads can jump at an epoch change: an entry made just before such a reading can share in rewards earned before it,
  and holders leaving just before it miss them. The fresh-price rule only bounds how old a reading can be, not this.
- **Deposits and cash.** The contract records depositors itself: `deposit` is payable (at least 0.1 NEAR) and credits its caller
  with the attached amount minus the storage its record adds (measured, priced at the chain's storage price). No method lets the
  agent or the guardian name a depositor. The agent's `issue_cash(account, tier, count)` turns that account's deposits into cash and
  records notes it may blind-sign, never more than the account's deposits not refunded and not already issued, and never for an
  account with a refund request waiting. A plain transfer, including an `ona-mint` spend, is never credited.
- **Refunds.** While the escape is open, or once the account's `request_refund` has waited the escape delay (even if the agent syncs
  every day), `refund_deposit` returns the account's own deposits never turned into cash, and nothing else.
- **Entries.** `enter(vault, cash note, owner_sig, outputs, expires_at)` (agent) spends a cash note for share notes. The owner signs
  `SHA-256("ONA-POOL-ENTER-V1" || H(contract) || nf || vault (u32 LE) || n (u32 LE) || (tier || count (u64 LE))*n || expires_at (u64 LE))`.
  The new notes cost the vault's price rounded up, paid from the cash; 0.002 NEAR goes to the storage of the nullifier and the owner
  key; what is left must be less than the vault's smallest note and stays in the cash, owned by nobody. Refused below a price of
  one thousandth of the initial price, over the vault's asset cap, after `expires_at`, for a note ever named in an exit request, and
  unless the note's cash tier has at least `min_live_notes` live notes.
- **Leaves.** `leave(vault, share note, owner_sig, outputs, expires_at)` (agent) spends a share note for cash notes, signed as
  `SHA-256("ONA-POOL-LEAVE-V1" || H(contract) || vault (u32 LE) || nf || n || (tier || count (u64 LE))*n || expires_at (u64 LE))`.
  The note is valued at the vault's price rounded down; the cash notes plus 0.002 NEAR must fit in it and leave less than the
  smallest cash note, which stays in the cash. The vault pays the whole note from its liquid funds at once, so cash is never backed by
  a promise and no loss can be dodged by leaving before it is read: when the money is staked, the leave waits until the agent brings
  it back. A leave must also leave in place the value of the payable exit requests waiting on that vault, so funds brought back for
  a holder who asked cannot go to another note first. A leave moves no value to the holders who stay. It counts in the vault's
  hourly exit window, and is refused for a note ever named in an exit request.
- **Exits.** `pay_exit(cash note, owner_sig, to, expires_at)` (agent) pays a cash note to the account the owner signed, only to an
  account that deposited, from the cash. The owner signs `SHA-256("ONA-POOL-CASH-EXIT-V1" || H(contract) || nf || H(to) || expires_at (u64 LE))`.
  0.002 NEAR is kept for the storage of the nullifier and the owner key. Each tier pays at most as many notes as were issued, and the
  agent pays only while the tier has at least `min_live_notes` live notes. An exit whose transfer comes back is kept for the account
  (`claim_owed`).
- **Exit limit.** Each account receives at most `deposited − refunded + accrued − received`. `accrued` grows on the account's cash
  still in the pool (`issued − received`) at the yearly rate set at creation (20 % by default, at most 100 %), and is brought up to
  date at every deposit, issue, refund and exit: money paid out and deposited again does not earn growth twice, and money only
  deposited, never turned into cash, earns nothing. Rounded up, saturating. It
  does not depend on any share price. It bounds what an accomplice of the agent can receive; the value itself is kept by the note
  counters.
- **Fee.** Zero by default. The guardian can announce up to 20 % of the gains above each vault's highest price read at a sync. A new
  rate takes effect after the admin delay, and gains are charged at the rate in force when the previous reading was made, so gains
  made before a change are not charged at the new rate. The agent collects it with `claim_fees`, from liquid funds beyond the value
  of the payable requests waiting on that vault, the only payment to the agent; it goes to the current agent, including fees earned under a previous one.
- **Requests.** `request_exit(vault_id, note, owner_sig, to, min_amount, expires_at)` is filed by the account it pays, which attaches
  the storage fee (336 bytes, an estimate, at the chain's storage price). The fee goes back to that account when the request is paid,
  withdrawn (`cancel_exit_request`) or dropped, less 80 bytes for the note's permanent mark: a note named in a request can afterwards
  only leave the pool by an exit, never enter or leave a vault. `vault_id` null is a cash note, the normal case. A share note is the
  fallback for a holder the agent does not serve: it is signed
  `SHA-256("ONA-POOL-EXIT-V2" || H(contract) || vault (u32 LE) || nf || H(to) || min_amount (u128 LE) || expires_at (u64 LE))` and
  shows the vault. A request is accepted only if it could be paid then, and if all the account's waiting requests in that list
  together fit its exit limit; at most four per account and 64 per list. Its date is the date it was filed: a request withdrawn and
  made again waits again, and a note withdrawn three times cannot be requested again. A request lasts at most 30 days: its
  signature must expire within 30 days of filing. A request counts as payable only while its note is unspent, its owner key has
  served no other note, the tier still has unpaid notes, its value covers the fee and the owner's minimum, and the account's limit
  covers it. Anyone can `drop_request` a request that has expired or can no longer be paid. The agent pays a listed request with `pay_request` (event `exit` for cash, `share_exit` for a
  share note).
- **Escape.** The escape is open when the agent makes no placement, sync or paid exit for the escape delay (7 days by default, from
  one minute to 30 days), and while a guardian announcement is waiting. The cash list is open as well when one of its payable
  requests has waited the escape delay, or the list is full and has stayed full that long (the clock starts when it fills and stops
  only when it is back to 32, so withdrawing and refiling requests does not restart it; the opening itself lasts only while the list
  is full). A vault is
  open on the same rules for its own requests. Then anyone can call `escape_exit` (only to the signed account that deposited, within
  its limit; the minimum of live notes does not apply), `sync`, and the fixed-amount `unstake` and `withdraw` of that vault; the
  agent cannot place in an open vault. While the agent is not silent (a request is overdue, or an announcement is waiting), the
  escape pays only notes with a request listed, so holders who asked are served before anyone else, unless that list is full and
  has stayed full for the escape delay (otherwise accounts filling it with requests nobody pays would keep everyone else from
  asking). As soon as the list is no longer full, others can ask again and the escape is back to listed notes only. A share-note
  exit without a request must leave the listed requests' value in place. Once the agent has been silent for the escape delay, every
  note can leave. With the agent gone nobody can sign cash, so share notes then leave their vault directly, which shows the vault.
- **Caps.** Per vault: most assets, and most NEAR moved per hour, counted separately for placements and for leaves and exits. For the
  cash, one hourly cap set at creation (at least two of the largest cash notes). Normal and escape exits share one window, so the
  rate never doubles. Hours are calendar hours, so up to two caps can pass around the turn of an hour. In an empty hour any single
  note passes, so a note worth more than the cap still leaves. Up to 64 new notes per issue, entry or leave.
- **What stays visible.** Everything in a call's arguments and in the events is public. `deposit`, `issue_cash` and `pay_exit` name
  the account (and `issue_cash` the cash tiers it gets); `enter` and `leave` name the vault and no account; neither kind names both.
  But: `get_holder` publishes each account's deposits, refunds, receipts and growth, so when vaults earn different rates the amount
  an account takes out can hint at its vault; entries can be linked to deposits by time and amount; `get_vault` publishes each
  tier's issued and paid counts, so the size of each set of holders is public; a `pay_exit` refused for lack of cash and accepted
  right after a `leave` from vault V points to V; a `withdraw` from V just before a `leave`, or a `leave` refused for lack of
  liquid funds, points to V and to the size of the note; a share-note request or escape exit shows the vault. The contract imposes
  no delay between these steps. The minimum of live notes per cash tier is not a delay either: a single account can fill a tier
  to reach it, and the last notes of a tier, which the agent cannot pay, leave only by a request and the escape delay, which opens
  the cash list (for listed notes only while the agent is active). Batching and delays are the agent's job.
- **Known limits, not fixed.**
  - The agent holds the note keys and blind-signs off chain. It can sign notes for an accomplice who deposited: the per-tier count
    limits the total paid and the exit limit bounds what the accomplice receives, but other holders of that tier can find it
    exhausted. It can also spend an owner's note in `enter` or `leave` and never sign the new notes.
  - A leave from a vault whose money is staked waits for the agent to bring funds back (days, not verified).
  - Filling a list is a race around 63/64: whoever controls the order of transactions in a block can withdraw and refile requests so
    the list never looks "not full" between them (ordering within a block on NEAR not verified). Keeping a list full costs the
    attackers 64 notes, their request fees, and the yield those notes lose while the staking pool returns the funds; it costs the
    other holders the yield of a vault unstaked in full. While a cash list stays full, the escape pays any cash note and the minimum
    of live notes per tier no longer applies to it, which weakens the anonymity of those exits.
  - What an entry or a leave leaves over stays in the cash, paid to nobody; each time less than one of the smallest notes. What is
    set aside in an emptied vault is owned by nobody too, and still bears that vault's later losses only through the price floor.
  - A key shared with `ona-mint` or another pool would let notes be forged: the contract can check uniqueness only among its own keys.
  - A callback that never comes back after a refused placement or a completed withdrawal leaves NEAR on the account that belongs to no
    compartment: `sync` corrects `placed`, not the liquid funds (no recovery method yet).
  - Storage: a depositor's record and a request are paid by whoever creates them (the request's bytes are estimated); nullifiers and
    owner keys are paid from the 0.002 NEAR kept per note.
  - A guardian can list a target that is not a real staking pool; the recorded code hash only lets others check. Withdrawal
    accounting assumes the target's transfer arrives.

## App skeleton
Local only, model faked and every fake response labelled `mode: mock`. Mission state machine with a plan frozen before any web
read; closed-schema reader output; payment gate with allowlisted templates, recipient list and amount cap (code, not model);
hash-chained journal with one-byte tamper detection; exposure report built from the journal; `dispatch(json) -> json`; CLI
(`ona demo`).

Journal keys, all derived from the mission's secret salt, which only the agent holds:
- the chain start `SHA-256("ona/j/v1" || salt)` is all a verifier needs (`verify_from`); it does not give the salt back;
- fingerprints are HMAC-SHA256 under a key derived from the salt, so whoever checks the chain cannot test guessed contents.
  Two equal contents in one mission give the same fingerprint;
- the checkpoint key (see Journal anchoring).

`Journal::seal(self)` consumes the journal, wipes its plaintext and produces the auditor form (format v2); if sealing fails,
nothing is wiped and the journal comes back in the error. The form: XChaCha20-Poly1305
per entry, entry keys from HKDF with the chain start as salt (a key opens its entry in that journal only), a commitment to the
entry key in each line, plaintext padded to 512-byte blocks. The sealed entry holds the line without its `prev` field, so one
disclosed entry does not give the chain head before it. `open_all` checks the sealed chain before decrypting and rebuilds the
exact plaintext lines. The sealed head changes at every seal; nothing anchors it yet. The plaintext journal still holds the chosen
firm, recipient, amount and transaction in clear. Nothing in the mission calls the sealing yet.

- **Pseudonyms** (`pseudonym.rs`): a local table gives each protected term (policy terms, plus terms declared with `protect` or the
  `protected` list of `open`, before the planner is asked; 2 to 200 characters, at most 64) a random pseudonym of 12 letters from
  `BCDFGHJKLMNPQRSTVWXZ` (no digit, so no pseudonym can supply a price or a delay). Texts and terms are compared on the view built
  by `pseudonym.rs`, in this order: HTML tags and comments removed (block tags as a line break); one level of decoding of numeric HTML
  references (with or without `;`, leading zeros, 128 to 159 as Windows-1252), named references (Latin-1 also without `;` and longest
  name first, Latin Extended-A, punctuation, invisible ones) and `%XX` runs (invalid UTF-8 bytes dropped); Unicode
  Default_Ignorable_Code_Point, U+2028, U+2029 and U+0085 removed; a dash or soft hyphen ending a line between letters kept as optional
  (a term matches with or without it); the dashes of `DASHES` folded to `-` and the apostrophes of `APOSTROPHES` to `'` (lists in
  README); NFKD (`unicode-normalization` 0.1.26) with every combining mark removed, Unicode lowercasing, `ß` as `ss`; every run of
  Unicode white space collapsed to one space. Pages are compared as `Web::fetch` returns them (the fake web returns text; HTML is
  handled the same way). A term matches as a whole word, or anywhere when
  written `*term*`. Occurrences are replaced longest term first, in the mission text before the planner and in each page before the
  reader; replies are put back locally, pseudonyms matched without regard to case. The gate (`check_terms`, also used for searches and
  messages) uses the same comparison and refuses any text that still contains a term. Rephrasings, undeclared terms, look-alike letters
  of other alphabets and double escapes are not caught. The table is dropped at `close`.
- **Plan**: every `read` sits in one block between `search` and `compare`.
- **Reader**: the reader is not asked for a firm: an offer counts for the firm the search tied the page to (`Web::source`); a
  `firm_id` given by the reader must be that firm. Each page is read once, a firm has one offer. Each excerpt is 12 to 200 characters
  and appears word for word in the text the reader was given (pseudonyms in place); pseudonyms are put back in the excerpts afterwards.
  Numbers are read from the excerpts one way only: digits grouped by three with a space, `.`, `,` or `'`; after `.` or `,` any other
  group ending the number is its decimals, never a second number ("12,5" is 12.50). One number must equal the price exactly (units × 100
  plus one or two decimals) and one number written without decimals must equal the delay. The reader's instructions state these rules.
- **Payment confirmation v2**: `digest = SHA-256(fields("ona/pay/v2", network, contract, mission_id, nonce_hex, to, amount_decimal))`,
  where `fields` is, for each field, its length as a little-endian u32 then its UTF-8 bytes; `nonce_hex` is 16 random bytes drawn at
  `prepare_payment` in lowercase hex, `mission_id` is random per mission, `amount_decimal` is the yoctoNEAR amount in base 10. The amount
  must equal the chosen offer's `price_cents × yocto_per_cent` (a rate in the policy, never from a page; zero refuses every payment).
  `prepare_payment` returns the six fields, the digest, the screen text and `amount_near`. A confirmation is checked against the
  mission's own payment, network and contract, and is used up by `pay`. It is a digest, not a signature by a separate device.
- **Exposure report**: rebuilt from the journal; `parties` names each party (search engine, each site, each contacted firm, the chain,
  the relay, the NEAR AI model through the relay) with its requests, bytes sent and bytes received. Bytes are those handed to the
  transport (path, headers, body), without HTTP framing or TLS; for the fake web they are the query, the handle and the message. A
  request that reached the relay is never counted as a gate refusal, even when only the attestation request left
  (`outcome: prompt_not_sent`). `content_readable_by_relay` and `warnings` say when a real call was made without quote verification.
- **CLI**: a line that is not UTF-8 or is longer than 64 KiB gets an error reply; the loop goes on.

## Journal anchoring (`crates/ona-core/src/checkpoint.rs`, `crates/ona-anchor`)
- Checkpoints of one journal form a chain. Checkpoint `n` has a commitment
  `SHA-256("ona/cp/commit/v1" || salt_n || n (u64 LE) || journal head || leaf of checkpoint n-1)` (zero before rank 0) and a
  leaf `SHA-256(0x00 || "ona/leaf/v3" || tag_n || commitment)`. `salt_n` and `tag_n` are HMACs of `n` under the checkpoint key,
  so leaves of one mission cannot be linked on chain. Nodes: `SHA-256(0x01 || left || right)`. Only the prefixes come from
  RFC 9162; the tree is not an RFC 9162 log.
- The tree always has depth 10 (1024 leaves). Real leaves sit at random positions and the rest are random filler leaves, so a root is
  always 32 bytes and an inclusion proof always 2 + 10 × 32 bytes (index, then siblings), whatever the batch size. The proof handed
  back is prefixed with the anchor's `seq` (8 bytes).
- `ona-anchor` receives `(client, tag, commitment)` and builds the leaf itself, so the tag it checks is inside the anchored leaf.
  It refuses a duplicate leaf, a tag already seen, more than 4 leaves per client per batch and more than 1024 per batch. It
  anchors one tree per hour even when empty, reads the anchor back from a final block, and hands out the proofs only if the chain
  holds that root and the batch's tags are saved. A refused anchor keeps the leaves for the next attempt with a new tree; a lost
  reply is recovered by reading the latest anchor. Tags are kept 7 days, in a file if one is given, and at most 1024 × 168;
  beyond that it refuses new leaves rather than forget tags early.
- The per-client limit holds only once `client` comes from something a sender cannot multiply for free (a spent request token is
  the plan); nothing checks it yet.
- `checkpoint::verify_checkpoints` and `journal::audit`, for an auditor holding the checkpoint key and an `AuditTrust`: every rank
  from 0 with no gap or duplicate, each leaf recomputed with the tag of its rank and found in the root the registry holds at its
  `seq` (read by the auditor), the first anchor inside the opening window the auditor knows from outside the agent, anchors in
  order and no more than the maximum gap apart, heads that are successive states of the journal, the last one its final head, and
  a journal that ends with `mission_close`. The opening window and the maximum gap must both be shorter than the 7-day tag
  retention, or the check refuses to run.
- What is guaranteed, under all these conditions: the aggregator is honest, kept its tag file, and was not changed during the
  mission (`SetAggregator` starts a new aggregator with no tags); the auditor's opening window is right. Then no second chain with
  the same checkpoint key that passes the check can have been anchored, because each of its ranks would have been submitted while
  the first chain's tag for that rank was still kept. A leaf sent with any other tag is a different leaf and does not pass.
- What is not: a parallel chain made with another checkpoint key from rank 0, unless the opening tag was recorded somewhere other
  than the agent when the mission started; anything once one of the conditions above fails. It proves what the agent wrote, not
  that it is true.
- The aggregator sees who sends a leaf and when; unlinkability holds on chain only. Someone who sees a tag and commitment in
  transit can submit them first.
- Not built: a program that receives leaves and delivers proofs over the network, and the agent side that submits checkpoints.

## Auditor key (`crates/ona-core/src/auditor.rs`)
The journal's 32-byte master key is sealed to the auditor's X25519 public key: ephemeral X25519 key, HKDF-SHA256 bound to both public
keys and to the journal's chain start, XChaCha20-Poly1305. Format v2: version (1) · ephemeral public key (32) · nonce (24) ·
ciphertext and tag (48). The auditor key is refused unless its fingerprint `SHA-256("ona/auditor-fp/v1" || key)` matches the one
the caller passes, which must come from elsewhere (pinned in the app or published in the registry). The caller's copy is wiped after
a successful seal and kept after a refusal or a failure. Nothing checks that the auditor received the sealed key. Copies made
elsewhere in memory are not reached.

## Chat retention (`crates/ona-core/src/vault.rs`)
Local history only if the user chooses it, otherwise automatic deletion after 24 hours. Chat results stay encrypted on the device with one key per chat, 24 hours from the first save by default; saving again does not
extend it. Expiry destroys the key, then the file, and a read is refused even if the purge has not run. `keep` is the user's choice
for one chat, `forget` deletes any chat at once. No chat result ever goes on chain.
- Keys are held by a `KeyStore` outside the vault directory (a key file inside it is refused). `FileKeyStore` is a stand-in until
  the keychain is wired in: whoever reads both the key file and the vault can decrypt what has not expired.
- The vault records the latest time it has seen, in the key store with the keys, and never goes back: removing that record
  removes the keys. A clock set back by more than 5 minutes destroys every chat that was going to expire (kept chats stay).
- The `keys` and `clock` files an earlier version kept in the vault directory are overwritten and removed when it opens.
- Expiry runs only when the vault is used: nothing purges while the app is closed, and setting the clock back before the app has
  seen a later time still shows a chat that should have expired. A scheduled system task is needed (not built).
- Deleted chat files and replaced key files are overwritten with zeros before release. On an SSD or a copy-on-write file system
  (APFS) that does not reach the old blocks, nor snapshots or backups; the app should exclude the vault from backups (not built).
- A file lock stops a second process from opening the same vault. Leftover temporary files and keys without a file are cleared at
  start. `chat_save` still answers 86400 seconds even when less is left (`Vault::expiry` gives the real end).
- What the user copies or backs up is their own choice and must be stated in the app.

## Encrypted model client (`crates/ona-core/src/e2ee.rs`)
NEAR AI encryption version 3 through the relay, written from the public `nearai/inference-proxy` sources and tested only against a simulated
enclave. Each encrypted request field is bound to the reply key, so a relay replacing `X-Client-Pub-Key` makes the request undecryptable. This
fixes the reply-key attack only if the NEAR AI gateway accepts version 3, which is **not verified**. Version 2 needs an explicit setting, and a
failed call never falls back to it. Version 3 does not bind a reply to one precise request, a replay carrying the original reply key is still
processed, and the relay still sees sizes and counters. Each request gets a new client key and a fresh attestation nonce. A reply counts only
if the signature comes from the attested model key (`provider_tee`) and covers the exact bytes sent and received. Every request carries
`max_tokens`, and a per-client budget stops calls before they spend. The relay sees the usage counters, so pricing must be flat per
request. TDX and NVIDIA quotes are not verified yet, so the relay that delivers the attestation report can answer with its own key,
read every prompt and sign replies of its own: nothing in the client detects it. The HTTP transport ignores proxies named in the
environment, follows no redirect and sends no `User-Agent`. A reply id must be 1 to 128 letters, digits, `-`, `_` or `.` before it is
used in a request path. Reply signatures are checked with strict ed25519 verification.

`crates/ona-core/src/quote.rs` checks a model attestation, not yet called by the client. **It is worth nothing until the Intel signature
check is implemented:** that check (meant for `dcap-qvl`, which was not available offline when this was written) and NVIDIA's service are
traits with no implementation, so nothing passes outside tests, and without the signature anyone can write a quote holding any value. The
Intel trait returns a verdict: TCB status, advisory ids, collateral issue date and the verified report body. The policy lists the accepted
TCB statuses and the oldest collateral accepted at a given time; the report fields are read from the verified body, which must equal the
quote's. With it, a quote passes only if MRTD and RTMR0 to RTMR2 are
on the caller's list, the event log replays to RTMR3, its `os-image-hash` and `compose-hash` events name a listed image and the hash of the
reported `app_compose`, `report_data = signing_address || nonce` (32 + 32 bytes), `mr_config_id = 0x01 || compose hash || 15 zero bytes`,
the enclave is not in debug mode, and the deployment hash is listed. `mr_config_id` alone proves nothing: the host chooses it. **The GPU
evidence is not bound to the TDX quote:** its nonce shows it is fresh, but a relay can copy a genuine payload from another machine.
Formats were checked on one real report (2026-11-10) that NEAR AI's official verifier accepted, not against the verifier's source. RTMR3
events carry no digest in the log: each is `sha384(event_type as u32 little-endian || ":" || event || ":" || payload)`. The listed values
in `observed_2026_11_10` were seen in that report, not published by NEAR AI, and change with each image update.

## Wallet (`crates/ona-wallet`)
Append-only encrypted file, synced before the action it protects: token secrets before the deposit, spending mark before a spend.
Each line is written in one write. The file is locked while open (a second open is refused) and must be readable by its owner only. A
seal file next to it (`<wallet>.seal`, XChaCha20-Poly1305 with the wallet key) holds the line count and a SHA-256 chain over the lines,
rewritten after each line: a wallet with fewer lines than its seal (older copy, lines cut from the end) or a different chain is refused,
and a missing wallet whose seal shows lines is refused instead of being recreated empty. A wallet with lines but no seal is refused by
design (a deleted seal could hide a rollback); `open_adopting_unsealed` adopts such a wallet explicitly, every line still decrypting.
Nothing is written to the file before every check has passed. A last line without a newline that does not decrypt (a crash during an
append) is cut and reported by `dropped_torn_line`, but only once the key is shown to be right by a complete line or by the seal;
otherwise the open fails and the file is left as it was. After a failed write, nothing more is written until the
wallet is opened again. Restoring the wallet and its seal together from one backup is detected only if the caller keeps `state()` out
of reach of that backup and opens with `open_expecting`. A spend mark needs a token of the wallet not already being spent; a release
needs a spend mark. Key storage in the operating system's keychain is not implemented.

The same file keeps the pool's notes: cash notes (no vault) and share notes (with their vault). A note's secrets (owner key, nonce,
blinding factor) are saved before its blinded point leaves; the note is kept once the agent's blind signature checks under the tier
key the contract publishes (`pk_raw`); then a status: held, spending (signed by its owner for an operation whose outcome is not
known, with the signature's deadline), spent. Allowed: held to spending; spending to spent, or back to held. `ona_wallet::pool`
builds the pool's tags, nullifiers and owner digests; an `ona-pool` test checks they are the contract's byte for byte and that a
note kept by the wallet is paid by the contract.

## Pool commands (`crates/ona-core/src/pool.rs`)
`pool_portfolio`, `pool_prepare`, `pool_execute` and `pool_recover` in `dispatch`, documented for the apps in
`docs/desktop/pool-commands.md`.
- **Prepare, then execute.** `pool_prepare` (`op` = `deposit`, `enter`, `switch`, `exit`, `exit_cash`) computes the plan from the
  contract's public figures and returns a summary and a `prepared_id` =
  `hex(SHA-256("ONA-POOL-PREPARE-V1" || 0 || network || 0 || contract || 0 || op || 0 || vault (u32 LE, u32::MAX for none) || amount || 0 || nonce))`
  with a random 32-byte nonce. The user confirms in the computer's app (no pool confirmation on the phone). `pool_execute` takes
  the id once, within 5 minutes: it is removed when used or expired, and checked again against the network and contract read at
  execution. The notes a preparation picks are reserved until then, so two preparations never take the same note.
- **Deposit.** A `deposit` call for the user's own wallet (ONA does not sign it), at least the contract's 0.1 NEAR minimum, with a
  0.01 NEAR storage margin (an estimate; the unused part stays refundable); then cash notes for the amount, largest tiers first,
  signed blind by the agent (`issue_cash`). The preparation lists the recommended amounts (100, 500 and 2,000 NEAR by default,
  `ONA_POOL_RECOMMENDED_NEAR`) and warns about any other amount: an unusual amount is easier to link to its exit. The deposit's
  `pool_execute` runs twice: the first call makes the cash notes (saved before anything leaves) and returns `sign_message`
  (`message`, `recipient` = the pool, `nonce`); the depositing account's own wallet signs it (NEP-413), and the second call carries
  `depositor_signature` (`public_key`, `signature`). The message is
  `"ONA pool cash issue v1\npool: <pool>\naccount: <account>\nnotes: " || hex(SHA-256((tier || blinded point)*))`, so the agent
  issues cash only for those points and only for that account; the contract refuses more cash than the account deposited. Both calls,
  and the wallet's signature between them, must come within the preparation's 5 minutes. When the second call is refused, the client
  asks the agent for the signatures it already made (tiers issued before the refusal), keeps those notes and forgets the others; if
  that question gets no answer (network, Tor), nothing is forgotten and `pool_recover` asks again later. A deposit abandoned between
  its two calls has its notes forgotten when the preparation expires.
- **Entries, leaves, exits.** An entry spends cash notes for share notes at the vault's price rounded up, computed from the public
  figures as the contract does (with `orphan`, the part of the vault no share owns); a leave spends share notes for cash notes at the
  price rounded down; a switch is leaves then entries, in one preparation since no account is named. The agent queues every entry,
  leave and cash exit (see Pool agent), so its first answer is "outcome unknown": `pool_recover`, later, collects the new notes, and
  a switch stops after its leaves, the entries following as a new operation once the cash notes are back. A request the agent
  drops (its owner's deadline passed while it waited, the escape spent its note, the chain refused it) is never signed: the app
  learns it from `pool_recover`, which holds the note again (`held_again`) once its deadline is more than 10 minutes past and the
  note is still unspent, or marks it spent if the escape took it. The new notes prepared for that request stay listed in
  `awaiting_signature`; forgetting them is not built. `exit` is only the leaves: it names
  no account and leaves the cash in the wallet. Paying an account is `exit_cash`, a separate operation, since a `pay_exit` right after
  a leave from vault V points to V; it checks the account's `exit_limit` (`get_holder`) first, and the account is checked as a NEAR
  account id before anything is signed. What a step leaves over, less than one of the smallest notes, stays in the pool's cash and is
  shown as `left_in_cash`. Values read from the contract are combined with checked arithmetic.
- **Notes and signatures.** Every note has a fresh owner key. Owner signatures follow ENTER-V1, LEAVE-V1 and CASH-EXIT-V1 and
  expire 24 hours after they are made, so the agent can batch them. A note is marked spending, with that deadline, before its
  signature leaves. The agent's answer is one of: success (the note is spent, its new notes kept); a certain refusal (nothing sent,
  or refused by the chain: the note is held again and the new notes made for it are forgotten, since no signature can come); an
  unknown outcome (sent, no answer: the note stays spending and its new notes stay waiting for their signatures). A failure after
  some steps of an execution succeeded returns those steps with the error.
- **Recovery.** `pool_recover` asks the contract `is_spent` for each spending note: spent → spent; unspent and more than 10 minutes
  past its signature's deadline (a margin for this computer's clock running ahead of the chain's) → held again; otherwise it keeps
  waiting. Then it asks the agent for the blind signatures of every note still waiting for one, and keeps those that check. When the
  agent cannot be reached it still reports what the chain told and lists the notes that wait (`agent_error`). With a second RPC
  endpoint (`ONA_RPC_URL_2`) recovery agrees on one final block as `ona-server`'s cross-checked reads do (the lower final block,
  same hash on the other endpoint at that height, heights at most 20 apart) and reads each `is_spent` on both at that block by
  `block_id`; any difference decides nothing; with one, that endpoint is trusted (a lying
  one can have a spent note held again, which the contract then refuses, or an unspent note marked spent, its value lost to the
  wallet). `is_spent` names a nullifier to the RPC endpoint: a spent one is public anyway, an unspent one says something about a
  later spend.
- **What leaves the computer.** `pool_portfolio` and every preparation read `get_config`, `get_cash` and `get_vault` for every vault,
  on final blocks, whatever the user holds; nothing goes to the relay. `exit_cash` also reads `get_holder` for the paid account,
  `pool_recover` `is_spent` for its spending notes. The agent receives the signed notes it must submit.
- **The agent.** `pool_agent::HttpAgent` speaks `ona-agent`'s HTTP API when `ONA_POOL_AGENT_URL` is set (`https`, or `http` to the
  machine itself, a final `/` ignored; no redirect, no proxy from the environment; any `e2ee::Transport` can carry it, Tor included).
  Each operation opens a new connection, so a cash issue and the entry that follows share none; through Tor a host passes
  `ona-tor`'s transport, which draws new SOCKS credentials each time it is created, so Tor keeps each operation on its own circuit
  (`IsolateSOCKSAuth`, Tor's default; not tested over the real Tor network). 200 is
  done; 202, a 5xx or a transport failure is an unknown outcome; any other status is a certain refusal. Without the variable the agent is
  `NoAgent`, which refuses every call before anything is sent; the notes prepared for a refused operation are forgotten.
- **Not built.** Configuring a pool wallet through the C bridge. Checking on chain that the user's deposit arrived before asking for
  cash (the agent checks it). The contract's minimum of live notes per tier and its waiting rules are not planned around: the agent
  may refuse, and the note is then held again. Tested against a fake contract, with a fake agent and with the real agent over HTTP on
  the machine itself.

## Pool agent (`crates/ona-agent`)
**Never run against a real chain, not in an enclave.** The program that acts on `ona-pool` for its users.
- **Keys.** One blind-signing BLS key per cash tier and per tier of each vault, in one file readable by its owner only, after the type
  line `ONA-POOL-AGENT-KEYS-V1`. The agent refuses to start unless they are the contract's keys and its account is the pool's agent.
- **Store.** A key-value log built like the relay's: created once with the keys (`init-store`), a first line binding it to the keys and
  the pool, readable by its owner only, held by one process through `<store>.lock` (stopped if that file is removed or replaced), every
  write synced, a torn last line cut at opening, rewritten atomically. Requests, their state and every signature made live there.
- **Requests** (HTTP on `127.0.0.1`, through the relay's strict HTTP front; routes in `crates/ona-agent/src/api.rs`). Checked off
  chain first, with the keys held here and this machine's clock (5 minutes of margin), before any RPC read: the note's BLS signature
  under its tier key and domain tag, its owner's signature for exactly this operation, the output tiers and counts against the
  blinded points (at most 64), valid points and the deadline. Then, at a pinned final block: the deadline again and the note not
  spent. A request is recorded before anything else and answered from the record when repeated: a done request returns the same
  signatures, a queued or sent one answers 202. A note serves one request: another request naming it is refused until the first is
  refused for good.
- **One owner signature, one set of points.** The first request carrying a note's owner signature fixes its blinded points (or, for
  a cash exit, its account) until that signature's deadline: a later request with the same signature and other points is refused,
  even after the first was refused. A refused transaction is public (note, owner signature, outputs, deadline): without this binding
  anyone could replay it with their own points and receive the new notes. The owner can sign again with another deadline.
- **Queue and batches** (`ONA_AGENT_WINDOW_SECS`, `ONA_AGENT_MIN_BATCH`, `ONA_AGENT_MIN_DELAY_SECS`, `ONA_AGENT_JITTER_SECS`; defaults
  15 minutes, 5, 10 minutes and 50 minutes). Entries, leaves and cash exits are queued, never sent on arrival. Each waits at least
  the minimum delay plus a random part of the jitter, drawn for each request, then leaves only in a processing window holding at
  least the minimum batch of requests of its class that can go now, in random order, once per window: the vault's price is made
  fresh (synced first) and the funds checked before the batch is counted, so k requests leave together or none does. Windows
  alternate between entries and leaves, and cash exits, so a payment never leaves in the window of a leave. A leave or a cash exit
  waits while the batch's outflows together exceed the liquid funds, less what the vault's listed exit requests may claim (the
  contract publishes how many there are, not their value: each counts as one of the vault's largest notes), or the hourly cap,
  counting what the agent already took out that hour; a refused call is public and names the vault. Exits made by others in the
  same hour (`escape_exit`) are not seen and can still use up the cap. Queued leaves are added to the reserve the planner keeps
  liquid. Nothing is queued while the escape is open on the cash (for an entry or a cash exit) or on the vault (for an entry or a
  leave), since anyone could then spend the note. A request sent with an unknown outcome is sent again only in a window of its
  kind, once per window. A request is not sent within 10 minutes of its owner's deadline; one whose deadline passes while
  it waits is refused and its note freed. Owner signatures last 24 hours, so a request can wait for a batch. With few users a request
  waits until enough others arrive; a batch of k requests hides each among k, not among all users (tested with a fake chain only).
- **Signing.** Only for work the agent itself did. A note request is signed only when one of its own transactions (the agent keeps
  their hashes) has a final success on both read endpoints (`tx`, `wait_until: FINAL`); a note being spent is not enough, since
  `escape_exit` or a listed request can spend it too. A request still queued whose note is found spent is refused; a sent one whose
  transactions all failed is refused; one whose outcome stays unknown is refused two days after its deadline. A cash issue is signed
  once a read through two RPC endpoints that agree on a final block shows the account's issued cash grew by the amount. The
  endpoint that sent a transaction is never believed alone. A vault
  read more than 50 minutes ago is synced before an entry or a leave, since the contract uses a price only within the hour.
- **Cash issue.** Needs a NEP-413 signature of the request's message (see Pool commands) by a key the chain shows as a full-access key
  of the account (`view_access_key`), and enough of the account's deposits not yet turned into cash, at most
  `ONA_AGENT_ISSUES_PER_HOUR` issues per account per hour (6 by default, counted in memory). Cash issues are not queued: the client
  waits for them. One `issue_cash` per tier; amounts are computed with checked arithmetic. An issue whose outcome is unknown is never
  resent: it is confirmed later from the account's issued cash, and blocks further issues for that account until then, until both
  read endpoints report a final failure of the transaction (`tx` by its hash; one endpoint alone decides nothing), or
  until two days have passed (a NEAR transaction stops being valid about a day after the block it names, not verified), when it is
  taken as never landed. Such an issue was sent, with no proof it failed: the account's deposits stay refundable on chain either way.
  Tiers already issued keep their signatures, available through `/signatures`.
- **Note operations.** An entry, leave or cash exit whose outcome is unknown is sent again, in later windows of its kind, until the
  note is seen spent (then confirmed as above) or its owner's deadline has passed at a final block (then refused, and the note
  freed): the contract spends a note once, so sending again cannot pay twice.
- **Crash between two writes.** The record is written first, then the owner signature's binding, then the note's (for a cash issue,
  the record, then the account's lock). Each tick restores a binding missing after its record, and removes a note binding or an
  account lock left behind by a request that finished; a binding or lock pointing to a finished request holds nothing meanwhile.
- **Kept only as long as needed** (`ONA_AGENT_RETENTION_SECS`, 7 days by default). A finished record keeps no account, vault, note or
  deadline, only its state and signatures. Finished records and the signatures kept for `/signatures` are deleted once the retention
  has passed; an owner signature's binding once its deadline has passed. After each purge the file is rewritten atomically without
  them; the old blocks are not wiped from the disk. Someone who seizes the disk reads the queued requests
  (notes, owner signatures, outputs, accounts paid), the last 7 days of signatures and the blind-signing keys: the keys alone let them
  sign notes, and the signatures let them match a wallet's notes to their blinded points. Logs print no signature.
- **Planner** (`crates/ona-agent/src/planner.rs`), every tick, from the vaults' figures and what the agent remembers: syncs every vault
  holding shares or placed funds before its reading is 45 minutes old (which also keeps the agent active, so the escape stays shut);
  withdraws unstaked funds after `ONA_AGENT_UNBOND_WAIT_SECS`; at a settlement (a new multiple of `ONA_AGENT_SETTLEMENT_SECS`, after
  `ONA_AGENT_MIN_ACTIVE` entries and leaves) places what exceeds the reserve (`ONA_AGENT_RESERVE_PERCENT` of the vault's assets), within
  the hourly cap, or unstakes what the reserve lacks. Defaults are not zero: 20 % reserve, a settlement every 30 minutes, after 10
  entries and leaves. Regular withdrawals (`ONA_AGENT_STEADY_YOCTO` every `ONA_AGENT_STEADY_SECS`, off by default; the period must
  be a multiple of 3 days) follow a fixed grid of multiples of the period, whatever the users do, so their timing says nothing
  about a leave. Each runs within an hour of its grid line or not at all: a line missed while the agent was down, or blocked by a
  settlement's unstake less than 3 days before, is skipped, never run late. Nothing is placed while an
  announcement is pending, while the escape is open, or in a frozen, open or busy vault; the agent's own `unstake` runs at most once
  per vault every 3 days, as the contract allows: the reserve refills slowly, and a leave larger than the liquid funds waits days.
- **Known limits, not fixed.** The agent sees every request in clear (note, outputs, account paid) and their arrival times; batches,
  delays and alternating windows only hide the link from people who watch the chain. The agent holds the blind-signing keys outside
  any enclave. Batches are made of separate transactions sent one after another in one window, not one transaction. A crash after a
  note request's transaction left and before its hash was written leaves the agent unable to confirm it: the request is refused
  two days after its deadline even if the transaction succeeded, and its new notes are never signed.
- **Not built.** Paying listed exit requests (`pay_request`: the contract has no view listing their nullifiers), noise moves, yield
  credited in whole notes, batching several users' entries into one transaction, limits per client on note requests (all clients
  arrive through one front, so limits are per route for all together; cash issues are limited per account), wiping the disk's free
  blocks, an enclave. Requests are served one at a time, chain calls included. The NEP-413 layout is written from the standard as
  recalled, not verified against a wallet; the RPC formats, `tx_status` included, are from the NEAR documentation, not verified
  against a node; gas budgets are not measured.

## Relay (`crates/ona-server`)
HTTP/1.1 front (`server/src/http.rs`) and a fake relay for front ends (`ona-mock-relay [port]`, localhost only, with a free-credit
route that exists only in that binary and also returns the credit's owner key, so a front end can sign `exchange_sig`). `NearRelayChain` connects it to the
contract. `gateway.rs` passes encrypted NEAR AI calls byte for byte and requires a one-use request token per chat. It forwards only the encryption headers and
`x-no-aliasing` (a short plain word), and sets `Content-Type: application/json` and `Accept-Encoding: identity` itself; free routes pass on no client header.
It follows no redirect and reads at most 4 MiB of reply. Before the token is spent, a chat must have exactly `model`, `messages`, `stream` and `max_tokens`,
no duplicated JSON key, one user message in lowercase hexadecimal, the encryption headers with `X-Encryption-Version` 2 or 3, a listed model, a body of at
most 64 KiB, and a message of at most `ONA_MAX_PROMPT_BYTES` bytes of text plus the 72 bytes of encryption. A reply is withheld above `ONA_MAX_TOKENS` +
`ONA_MAX_PROMPT_BYTES` + 64 tokens: the largest prompt at one token per byte (an assumption about the tokenizer, not measured) plus an estimate of the chat
template (not measured). It is a last resort, since the call is already paid, so a request token must be priced for that much. Service errors keep their
status and lose their text. `ona-relay` is the program that runs all this; it uses no local model (`NoModel`), and only `Relay::chat`, used by tests and the
mock relay, labels its replies `mode: mock`. It has not run yet. No padded batches or enclave yet.

**Free routes.** An attestation needs an unused request token in `X-Ona-Token`, which it does not spend: 4 per token, counted until the token is spent
(never reset while the relay runs, and kept when an unbilled chat returns the token), plus 600 per minute across all clients. At most 65 536 unused tokens are followed: filling that table costs 655 credits
at 100 tokens per credit, and then new tokens get no attestation until some are spent. A signature needs the token spent on the chat it signs, for that
reply's `id` (a reply without `id` gives none): 4 fetches per chat for 10 minutes, a fetch the service does not answer with 200 is not counted, and the
global limit never refuses it, so a paid chat can always collect its signature. These counts live in memory: a restart gives unused tokens their
attestations back and drops the tickets. Showing the same token on the attestation, the chat and the signature lets the relay link these three requests,
as their timing already does.

The relay is not trusted with content: with encryption version 2 a dishonest relay can replace the client key and read the reply. Version 3 closes this
only if the NEAR AI gateway accepts it, which is not verified.

Parsing is strict (`HTTP/1.1` only, one `Content-Length` of digits, no `Transfer-Encoding`). Each connection has 5 seconds for its request line and headers,
30 for the whole request and 30 to receive the reply. Connections are served by 32 threads with a queue of 256, and a full queue answers 503: 32 slow clients
still fill the pool, so the onion service in front must limit them. Chain and model calls run without holding the relay state, and so do the checks that
need only the configuration: credit, signatures, blinded points, chat policy and request token signature. After a panic while the state was held, every
request answers 503 and the log asks for a restart. Signing a batch of claims still runs under the lock.

**Credit exchange.** The body carries the credit, its claim signature (`claim_digest_until`) with `expires_at`, and `exchange_sig`. All are checked before
anything else. A new exchange needs `expires_at` between 30 minutes and 7 days ahead of the relay's clock (checked before any chain read; a client
collecting a finished exchange may hold an expired one by then). The expiry is stored with the claim and sent unchanged after a restart. A pending claim
within 5 minutes of its expiry by this machine's clock is not sent. A sent claim is given up only when a final block, read through both endpoints before the
view that still shows the credit open, is past its expiry: the contract judges by block time, and a sent transaction can land hours later. Both answer
410 and the credit may be exchanged again with a later expiry. A new request for a given-up credit always reads the chain: if the earlier claim landed
after all, the relay signs the points of that claim; if someone else spent the credit, it refuses. Batches hold at most 28 claims. State is written durably before each irreversible step. The relay signs only what a final block, read through
two RPC endpoints that must agree (as for the signer), shows as claimed by this relay: `relay_claim` results come from one endpoint and decide nothing
alone. `is_spent` is read before `spent_by_relay`, so a claim landing between the two reads stays open instead of reading as spent by someone else.
Spent elsewhere refuses, and anything else, such as the hourly limit, stays pending. A credit found spent is remembered, so replaying it costs no further
chain read. Before a claim whose earlier one had an unknown outcome, the relay asks for that transaction's status; if it landed, the batch is not sent
and the next flush reads the chain. Pending credits are sent in nullifier order, without a retry count. Both endpoints must report the expected chain id.

**Store.** Request tokens are recorded as used before the model call, and returned durably only when the service refused the connection or answered 401,
402 or 429. The store is created once with the request key (`init-key`, which removes the key file again if the store cannot be made), names that key on
its first line, is readable by its owner only and held by one process through `<store>.lock`; if that lock file is removed or replaced, the store stops.
The relay refuses to start without its store, so a lost store cannot silently make used tokens valid again. Restoring an old copy of the store still does:
detecting that needs a monotonic counter, for example in an enclave. Two relays with separate stores and the same key could each sign for one credit; run
one. The store cuts a last line without a newline at startup, stops after a failed write until restarted, is rewritten with one line per credit and per
used token, and keeps them forever: with no key epoch, nothing can be purged.

## NEAR RPC client (`crates/ona-near`)

**The RPC node is a trusted component.** Views (`pending_deposits`, `relay_claim` results, `is_spent`, access keys), nonces and block times
are taken as the node gives them; `view_final` protects against a reorganization, not against a lying node, and no light-client proof
is checked. A dishonest node can therefore make the signer blind-sign a deposit that does not exist, or make the relay accept or refuse a
claim wrongly. Only an operator-run node, or several independent nodes compared, would remove this; neither is built.

What the client does refuse is being made to sign something else than what its caller asked for:
- The transaction encoder takes a block hash of exactly 32 bytes, and a `block_hash` from the node that is not base58 of 32 bytes is an
  error. A longer value would have let the node append actions of its choice to the signed bytes. The nonce is `nonce + 1`, refused on
  overflow. Both are read with finality `final`. Signer and receiver must be well-formed account ids.
- `ONA_RPC_URL` must be `https`, or `http` to `127.0.0.1`, `localhost` or `[::1]`. Plain `http` to a `.onion` address is accepted only by
  the client that sends everything through Tor (`Client::with_agent`, used by `ona_tor::near_client`), never by `Client::new` or
  `Client::connect`. Redirects are not followed (a 3xx is an error), proxy variables from the environment are ignored, and the body of an
  HTTP error is read.

What a result means. A send uses `send_tx` with `wait_until: FINAL`. A result is read only when it states `final_execution_status:
"FINAL"`, lists its receipts (`receipts_outcome`) and has a status of `SuccessValue` or `Failure`; anything else is treated as an unclear
answer (below). The outcome then keeps two things apart:
- `failure`, the status of the transaction itself, which follows the chain of promises its first receipt returned;
- `failed_receipts`, every receipt that failed, including a sub-call a contract handled in a callback (`on_spend_payout` in the mint;
  `on_place`, `on_unstake`, `on_sync` in the pool) and promises it did not wait for. `Outcome::require_all_receipts_ok()` fails if either is set.

Which to use: a caller that needs every effect to have happened (a transfer, a deployment, every call of `ona-crowd run`) uses
`require_all_receipts_ok()`. A caller of a contract method whose callback handles a failed sub-call reads `failure`, then the contract's
state, because a failed receipt there does not mean that nothing happened (a nullifier can be consumed while the payment came back).
`ona-deploy` and `ona-crowd` use `require_all_receipts_ok()`; `ona-sandbox`, the signer and the relay read `failure`, as before. Neither
guarantees that the node reported every receipt or that the contract reached the state the caller expected: when that matters, read the
state again. Whether nodes always return `final_execution_status` is not verified; a node that leaves it out gets every send reported as
of unknown fate.

A failed send never means "did not happen". The outcome carries the transaction hash (SHA-256 of the unsigned transaction, as NEAR defines
it; not checked against a node). A JSON-RPC error named `INVALID_TRANSACTION`, `PARSE_ERROR` or `REQUEST_VALIDATION_ERROR` is a refusal. Any
other answer that is not a final result naming this transaction (timeout, HTTP error, unreadable reply, a result that is not final or
lists no receipts, a result for another transaction hash) makes the client ask `tx` for its own hash, up to three times, two seconds
apart, accepting only a final result naming that hash. If the node still cannot say, the error is `TxUnknown` with the hash. The
transaction is never re-sent. It can still be included until its block hash expires, so a caller must check that hash before repeating the
action. The error names, the `tx` method and its parameters come from the NEAR RPC documentation and were not checked against a node.
Two programs using the same key read the same nonce: one of them is refused, with no retry.

The account key file is opened once without following symbolic links, and must be a regular file of at most 4 KiB, owned by the current
user, readable by them only. The decoded key material is wiped from memory after use; the key text in the caller's environment is not.

Since the `ona-sandbox` run of 2026-11-10 this client changed (required finality, failed receipts listed, status checks). It has not run
against a node since.

## Deployment (`crates/ona-deploy`)

The contracts have no access key, so a wrong role can never be corrected. Before sending, `ona-deploy` refuses: a network or chain id
containing `mainnet`, an RPC address containing `mainnet` or not https, a parent account ending in `.near`, a non-`.testnet` parent when the
chain id is `testnet`, then a node reporting another chain id than expected (`ona_near::check_network`, also used by `ona-crowd`). Every
role must be a well-formed account that exists, and no account may hold two roles (mint: signer, relay, guardian; registry: two owners
and the aggregator; pool: guardian and agent). Amounts are computed without wrapping: a tier worth more than a `u128` is refused, and so
is a funding of zero for any of the three contracts. The plan
and the SHA-256 of the contract are printed, and the operator must type the account name. Afterwards the tool checks that the account
has no access key and that its `code_hash` is the base58 SHA-256 of the file sent (that NEAR's `code_hash` is this hash is not checked
against a node). Comparing names and chain ids is not a full guarantee: a node lying about its chain id is not detected.

## Reproducing the contract hashes

`verify.sh` builds each contract with Rust 1.99.1, `--locked`, the `contract` profile (`opt-level = "z"`, `lto`, one codegen unit,
`panic = "abort"`, overflow checks), the flags of `crates/<contract>/wasm-build.toml`, and three path rewrites: `$CARGO_HOME` to `/cargo`,
the standard library sources of the toolchain to `/rustc/<rustc commit>` (the path rustc uses when those sources are not installed), and the
repository to `/ona`. `RUSTFLAGS` and its variants are unset first, since they would replace those flags, and a path containing a quote,
a backslash or `=` is refused. It then fails if a wasm contains the repository path, `$CARGO_HOME`, the toolchain path, the home
directory, `/Users/` or `/home/`, and prints each SHA-256.

To check a deployed contract: build the same commit with `verify.sh` and compare the printed SHA-256, in base58, with the `code_hash` of
the account (`view_account`). Measured: the registry built here had 26 paths under the home directory without the rewrites and none with them. **Not
verified:** that a second machine gets the same bytes. A different Rust version, a different `CARGO_HOME` layout or another crates.io index
directory name gives other bytes, and C code compiled by build scripts was not checked. No reference hash is published yet. The Rust
version is written in INSTALL.md only: the repository has no `rust-toolchain.toml` yet.
