# ONA build spec v1 (2026-11-10)

**Status: draft, not reviewed by a cryptographer. The contract must not hold real funds.**

## Layout
Under `crates/`: `ona-token` crypto and token format · `ona-mint` NEAR contract · `ona-registry` NEAR contract · `ona-signer` issuing
loop · `ona-server` relay · `ona-wallet` encrypted wallet file · `ona-core` local mission core and CLI · `ona-sandbox` deployment and
gas harness · `ona-anchor` journal anchoring aggregator · `ona-pool` NEAR contract holding the funds the agent places · `ona-near` NEAR
RPC client · `ona-deploy` deployment tool · `ona-crowd` crowd simulator.

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
The account that holds the funds the agent places. Never deployed, tested on the mocked NEAR VM only, with share notes made by
`ona-token`. No staking pool has been called for real.

- **Roles.** Created by `ona-deploy pool` with no access key. The `guardian` lists vaults, freezes them, sets the agent account and the
  fee. The `agent` is an account set by the guardian. Checking that the agent's key lives in an attested enclave is done outside the
  contract and is not built. A new agent (`set_agent`) or a new vault (`add_vault`) is announced and takes effect only after the admin
  delay (set at creation, from 7 to 30 days, 7 by default: at least as long as a staking pool is expected to take to return unstaked
  funds, which is not measured here); the current agent keeps working meanwhile, and the escape is
  open to everyone until every announcement has taken effect. Freezing a vault and setting the fee take effect at once: neither moves
  money out.
- **Vaults on a list.** Each vault has an adapter type and a target account. `staking` calls only `deposit_and_stake` (with the amount
  attached), `unstake {amount}`, `withdraw {amount}` and the view `get_account_total_balance {account_id}`, as named in the standard
  NEAR staking pool (`near/core-contracts`, `staking-pool`); not run against one. `lending` cannot be added: no lending interface has
  been checked against its source, so its adapter is not implemented. The guardian also records the SHA-256 of the code it checked
  at the target, shown by `get_vault`. A contract cannot read another account's code, so this hash is not verified by the pool;
  anyone can compare it with the code the RPC returns. A vault runs one call at a time, numbered: only the callback of the call in
  progress frees the vault, and a call whose callback never returns stops blocking after one hour. Gas for those calls (50 Tgas,
  callback 20 Tgas) is not measured.
- **Unstaking.** Whether each `unstake` on the standard staking pool restarts the lock on everything already unstaked is **not
  verified**: its code could not be read here. The pool guards against it anyway: at most one `unstake` per vault every 3 days (a
  design margin, not a measured lock length), and the agent cannot unstake on a vault while the escape is open or an exit request
  on it is overdue; others can.
- **Share notes.** Blind BLS notes as in `ona-mint`, with one key per tier and per vault (a key cannot be listed twice) and the tag
  `ONA-POOL-V1:<network>:<contract>:<vault>:BLS12381G1_XMD:SHA-256_SSWU_RO_`. Message `tier || pk || nonce`. Nullifier
  `SHA-256("ONA-POOL-NF-V1" || vault (u32 LE) || tier || pk || nonce)`. A tier carries a fixed number of shares, so a note's value in
  NEAR follows the share price.
- **Share price.** `(liquid + placed - fee owed) / shares`, rounded down; 10^-6 NEAR per share in an empty vault. `placed` is set by
  `sync`, which reads the target's own balance for the pool, never a number given by the agent.
- **Deposits.** The contract records depositors itself: `deposit` is payable, credits its caller with the attached amount minus
  0.001 NEAR for storage (at least 0.1 NEAR), and adds it to the unassigned funds. No method lets the agent or the guardian name a
  depositor. While the escape is open, or once the account's `request_refund` has waited the escape delay (even if the agent syncs
  every day), `refund_deposit` returns unassigned money to depositors. `record_entry` names no depositor, so the contract does not
  know whose money went to a vault: each account gets at most its share of the unassigned funds, its deposits not yet paid back by a
  refund or an exit over everyone's. A refund lowers the account's exit limit by the same amount. When no vault has grown (best growth
  1), an account whose money was placed therefore cannot take others' unassigned money and also exit its notes. When a vault has grown
  by a factor g, exit limits are multiplied by g, so an account whose own vault did not grow can still refund up to (1 − 1/g) times
  its deposit from others' unassigned money and exit all its notes.
  The cost is that an account whose money was never placed may get
  only part of it back by refund when others' money was placed. There is no other way back. This was chosen over reading `ona-mint`'s records: a mint spend arrives as a plain
  transfer that names nobody, and reading the mint from the pool would need a cross-contract call per deposit. A plain transfer,
  including an `ona-mint` spend, is never credited and never counted as unassigned, so it cannot be given to a vault.
- **Entries.** The agent's `record_entry(vault, tier, count)` moves unassigned funds, as counted by the contract and never read from
  the balance, into a vault at the current price and records the notes it may sign; it names no depositor. A withdrawal in flight is
  tracked per vault (`withdrawing`) and becomes liquid funds of that vault only, never unassigned. Entries stop below a share price
  of one thousandth of the initial price.
- **Exits.** `pay_exit` (agent) pays one note to the account the note owner signed, and only to an account that deposited. The owner
  signs `SHA-256("ONA-POOL-EXIT-V1" || H(contract) || vault (u32 LE) || nf || H(to) || min_amount (u128 LE))`. Each tier pays at most
  as many notes as were recorded. Each account receives at most its deposits minus its refunds, times the best growth of any vault's share price (highest
  over lowest seen, the lowest never counted below one thousandth of the initial price), minus what it has received, computed
  without overflow: the contract does not know which vault an account chose, so it allows the best case. A vault worth nothing
  refuses its own notes as worthless and blocks no other exit.
  0.001 NEAR is kept from each exit for the nullifier's storage. An exit whose transfer comes back is kept for the account
  (`claim_owed`). The notes hide which vault an account chose. They do not hide who owns the funds.
- **Fee.** Zero by default. The guardian can set up to 20 % of the gains above each vault's highest price after fees, so a recovery
  after a loss is not charged twice; gains made before a change are not charged at the new rate. The agent collects it from liquid funds
  with `claim_fees`, the only payment that goes to the agent: never more than the fee charged, nothing while the rate is zero.
- **Escape.** If the agent makes no placement, sync or paid exit for 7 days (set at creation, from one minute to 30 days), or while a
  guardian announcement is waiting, anyone can `sync`, `unstake`, `withdraw` and `escape_exit` notes, still only to the signed account
  that deposited, whether or not the agent ever served it, and depositors can `refund_deposit`. Entries, unstaking, withdrawals, fees
  and `set_agent` do not restart the delay. Separately, anyone can `request_exit` with a note and its owner's signature, attaching
  0.001 NEAR that the pool keeps for the request's storage (at most 64 waiting per vault). If that exit is still unpaid after the same
  delay, even while the agent is active: `escape_exit` opens for that note, anyone can `sync`, `unstake` and `withdraw` on that vault,
  and the agent cannot `place` in it until the exit is paid. A request is accepted only if the exit could be paid then (tier, value
  above the storage fee and the owner's minimum, the account's exit limit), at most four per account and vault; the paid account can
  withdraw it (`cancel_exit_request`), and a request that can no longer be paid, for instance after a loss, blocks nothing. A note
  keeps the date of its first request even if the request is withdrawn and made again. A vault whose list of 64 requests stays full
  for the escape delay (the clock stops only when the list is back to 32) opens the same way, so keeping it full cannot shut out an
  honest holder. When a vault opens this way, `escape_exit` works for every note of that vault.
- **Switching vaults.** `switch_vault(from, note, owner_sig, to_vault, outputs)` (agent) spends a note of `from` with the same checks
  and nullifier as an exit, and records `outputs` (tier and count) as notes the agent may blind-sign in `to_vault`. The owner signs
  `SHA-256("ONA-POOL-SWITCH-V1" || H(contract) || from (u32 LE) || nf || to_vault (u32 LE) || n (u32 LE) || (tier || count (u64 LE))*n)`.
  The old note is valued at `from`'s price rounded down, the new notes at `to_vault`'s price rounded up, in favour of both vaults'
  holders. The new notes cannot cost more; what is left over must be less than `to_vault`'s smallest note and goes to the pool's
  reserve, which pays nobody, so no share price and no exit limit jumps. `to_vault` must be listed, active, not frozen and above the
  price floor, and its asset cap counts what it is owed, as entries do. A note with an exit request waiting cannot be switched.
  Nothing is paid and no account's counters change, so exit limits are unchanged. Debts are kept per pair of vaults (and per vault
  towards the reserve, `get_debt`); both share prices count them. `settle_switch(from, to, amount)` moves liquid funds inside the
  pool, only up to what `from` owes `to`, by the agent, or by anyone once the escape is open, `from` is overdue, or a vault `from` owes
  is overdue; the agent can then no longer unstake `from`. Until settled, the new notes can be paid only from `to_vault`'s own liquid
  funds. A vault that owes switched value cannot place more until it settles. A loss in `from` before settlement falls on `from`'s
  remaining holders: the debt is a fixed amount of NEAR. If `from` no longer holds enough to cover what it owes and its fee
  (liquid + placed + due < owes + fee owed), no entry and no switch can bring new money into it, so a new holder never pays that
  debt. What it cannot pay is a loss for its creditors: their share prices still count the full debt, so they show more than can be
  paid until settlement, and nothing writes the debt down (not implemented). The reserve from switch leftovers is locked: no method
  pays it out, and each leftover is less than the destination vault's smallest note.
- **Escape speed.** Exits through the escape are limited by the vault's hourly cap, like other exits, including during an admin
  delay: a guardian announcement gives holders 7 days or more, but at most one hourly cap per hour per vault can leave that way.
- **Caps.** Per vault: most assets, and most NEAR moved per hour, counted separately for placements, for exits paid by the agent and
  for exits paid through the escape, so neither placing nor normal exits can use up the escape's window. Up to 64 notes per entry.
- **Known limits, not fixed.** The agent holds the note keys. It can sign notes for an accomplice who deposited: the per-tier count
  limits the total paid and the per-account limit bounds what that accomplice receives, but other holders of that tier can then find
  it exhausted and lose. A vault's low price after a loss raises everyone's exit limit, up to a thousand times the deposit. The agent
  can still keep the general escape closed by syncing, but not the escape of a vault where a payable request waits or whose request
  list stays full. Someone holding many notes can fill a vault's 64 request slots, at 0.001 NEAR each; after the escape delay this
  opens that vault's escape instead of blocking it. A guardian can list a target that is
  not a real staking pool; the recorded code hash only lets others check. Withdrawal accounting assumes the target's transfer arrives;
  a vault's call that times out is corrected only by the next `sync`.

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
  `on_place`, `on_done`, `on_sync` in the pool) and promises it did not wait for. `Outcome::require_all_receipts_ok()` fails if either is set.

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
