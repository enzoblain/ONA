# Pool commands (`ona-core`)

The desktop apps drive the `ona-pool` contract through `ona-core`'s JSON dispatch: the same commands go through `ona` on
stdin and through the C bridge (`OnaCoreBridge`, `ona_core_dispatch`, which passes the JSON as it is). Every reply has `ok` and
`mode` (`mock` against the fake pool of the tests, `real` when read from a NEAR node).

Status: the commands run end to end only against a fake contract, with a fake agent (`crates/ona-core/tests/pool.rs`) and with
the real agent, `ona-agent`, over HTTP on the same machine (`crates/ona-agent/tests/agent.rs`). Without `ONA_POOL_AGENT_URL`,
`pool_execute` answers `no connection to the pool agent yet`, no agent call is made, no note is spent, and the notes it had
prepared for the operation are forgotten. The pool contract and the agent have never run on a real chain.

**Do not send a deposit from a NEAR wallet while no agent runs for the pool:** nobody could turn it into cash notes, and the money
would wait in the contract until the account asks for a refund (`request_refund`, then `refund_deposit` after the escape delay).

## Setup

`ona` answers these commands when started with `ONA_WALLET_FILE`, `ONA_WALLET_KEY_FILE`, `ONA_POOL` and `ONA_RPC_URL`, and
optionally `ONA_POOL_RECOMMENDED_NEAR` and `ONA_POOL_AGENT_URL` (see `docs/INSTALL.md`). Without the first four every pool command answers
`no pool wallet configured`. The C bridge creates its core without a pool wallet, so through the bridge the commands answer the
same error until the app configures one (not built).

## Confirmation: prepare, then execute

Every operation has two steps.

1. `pool_prepare` computes what will be done from the contract's public figures and returns a `summary` and a `prepared_id`.
   Nothing is signed or sent. The app shows the summary and asks the user to confirm **on the computer**. There is no pool
   confirmation on the phone.
2. `pool_execute` with that `prepared_id` does it. The id works once, and only for 5 minutes (`summary.expires_at`, nanoseconds);
   it is bound to the network, the contract, the operation, the vault, the amount and a random nonce. An unknown, expired or
   used id is refused. The notes a preparation picks are reserved until it is used or expires: two preparations never take the
   same note.

Amounts are yoctoNEAR in strings (1 NEAR = 10^24). An amount must be a sum of whole notes: build it from the `note_value`s of
`pool_portfolio` (or of the contract's cash tiers for a deposit). What a step leaves over (less than one of the smallest notes it
could become) stays in the pool's cash, owned by nobody: the summary shows it as `left_in_cash`, so the user sees what is lost.

## Commands

### `pool_portfolio`

Request: `{"cmd":"pool_portfolio"}`.

Reply: `cash` (`tiers` with `tier`, `note_value`, `held`, `spending`; `value`; `spending_value`; `awaiting_signature`), `vaults`
(for each vault where the user has notes: `vault`, `share_price`, `frozen`, `tiers`, `value`, `spending_value`,
`awaiting_signature`), `vault_count`, `total` (held notes only). `spending` notes are signed for an operation whose outcome is not
known yet: they are not available. It reads the contract's configuration, the cash and **every** vault, whoever runs it, and
sends nothing to the relay. The values use the contract's public share prices.

### `pool_prepare` / `pool_execute`

| `op` | Fields | What the user confirms | Summary fields |
|---|---|---|---|
| `deposit` | `account`, `amount` | sending `wallet_call` from their own NEAR wallet: ONA does not sign it | `account`, `cash_notes`, `recommended`, `warning` (if any), `wallet_call` (`receiver`, `method`, `args`, `attached`), `fees` |
| `enter` | `vault`, `amount` (cash to spend, or `"all"`) | which vault, how much cash, the shares received | `vault`, `shares_value`, `left_in_cash`, `fees` |
| `switch` | `from`, `to`, `amount` (shares of `from`, or `"all"`) | moving shares to another vault without an exit | `from`, `to`, `share_price`, `new_shares_value`, `left_in_cash`, `fees` |
| `exit` | `from`, `amount` (shares of `from`, or `"all"`) | turning shares of `from` into cash notes, kept in the wallet | `from`, `cash_value`, `share_price`, `left_in_cash`, `fees` |
| `exit_cash` | `to` (the account that deposited), `amount` (cash) | cash paid out to `to` | `to`, `received`, `exit_limit`, `fees` |

Every summary also has `op`, `amount`, `network`, `contract` and `expires_at`.

- **Deposit.** The amount must be at least the contract's minimum (0.1 NEAR) and a sum of cash notes. `recommended` lists the
  amounts the app should offer first (100, 500 and 2,000 NEAR unless configured): a common amount is harder to link to its exit.
  Any other amount comes with a `warning` to show the user. The user sends `wallet_call` with their own wallet (`attached` is the
  amount plus a storage margin; the unused margin stays refundable). Then `pool_execute` runs **twice**:
  1. `{"cmd":"pool_execute","prepared_id":…}`: `ona-core` makes the cash notes (saved before anything leaves) and replies
     `complete: false` with `sign_message` (`message`, `recipient`, `nonce` in base64). The app asks the **same wallet** to sign it
     as an off-chain message (NEP-413 `signMessage`, with that message, recipient and nonce).
  2. `{"cmd":"pool_execute","prepared_id":…,"depositor_signature":{"public_key":"ed25519:…","signature":"<base64>"}}`: the agent
     checks that the key is a full-access key of the depositing account and that it signed exactly these notes, then issues the
     cash and signs it blind. Reply `complete: true`.

  Both calls, and the wallet's signature between them, must come within the preparation's 5 minutes. If the second call is
  refused, `ona-core` asks the agent which notes it had already signed (tiers issued before the refusal), keeps those and forgets
  the others; if the agent cannot be reached to answer, nothing is forgotten and the error says to run `pool_recover` later. If
  the second call never comes, the notes made by the first are forgotten when the preparation expires. The message
  names the pool, the account and a hash of the notes, so the signature cannot serve anyone else's notes; the contract refuses
  more cash than the account deposited. The NEP-413 layout is not verified against a real wallet yet.
- **Entries, leaves and cash exits are queued.** The agent never sends them on arrival: it waits a minimum delay plus a random
  part, then sends them in a batch with other users' requests (see `SPEC.md`, Pool agent). So `pool_execute` on `enter`, `exit`,
  `switch` or `exit_cash` normally answers `outcome unknown, run pool_recover later`; the app runs `pool_recover` later (minutes to
  hours; at most the owner signature's 24 hours, after which the note is held again) to collect the new notes.
- **A request the agent drops.** If the owner signature expires while the request waits, the escape spends the note, or the
  chain refuses the call, the agent never signs it and frees it. The app learns it only through `pool_recover`: once the deadline
  is more than 10 minutes past, an unspent note comes back as `held_again` (it can be used again), a note the escape took is
  counted in `spent`. The new notes prepared for the dropped request stay counted in `awaiting_signature` (forgetting them is not
  built), so the app should not read that count as money on its way. While the escape is open the agent refuses new requests at
  once (a certain refusal: the note is held again).
- **Exit in two steps.** `exit` only turns shares into cash notes and names no account. Paying the account is `exit_cash`, a
  separate operation the app can offer later: a payment right after a leave from a vault would point to that vault. A `switch` is
  prepared as leaves then entries, since no account is named, but stops after its leaves while the agent queues them: once
  `pool_recover` has the cash notes, the entries are a new `enter`.
- **Exit limit.** `exit_cash` reads the paid account's limit from the contract (`get_holder`) and refuses more.

`pool_execute` replies `executed` (the operation), `complete` and `steps` (what was done, in order). If a step fails after others
succeeded (in a `switch` or with several notes), the reply has `complete: false`, the `error` and the steps already done. If the
first step fails, the reply is an error.

### `pool_recover`

Request: `{"cmd":"pool_recover"}`. To run after an interruption or an `outcome unknown` error, and at start-up.

For each `spending` note it asks the contract whether the note is spent (`is_spent`): a spent note is marked spent; an unspent
one whose owner signature expired more than 10 minutes ago (a margin for this computer's clock running ahead of the chain's) is
held again, since the operation can no longer happen; others keep waiting. Then it asks the agent for the blind signatures of
every note still `awaiting_signature` (a lost answer, a deposit whose cash was never finished) and keeps those that check.

Reply: `spent`, `held_again`, `still_spending`, `signatures_recovered`, `awaiting_signature`, and `waiting` (the vault and tier of
each note still waiting for a signature). If the agent cannot be reached, the reply is still a success with what the chain told,
plus `agent_error`.

With a second RPC endpoint (`ONA_RPC_URL_2`, run by another operator), recovery first agrees on one final block: the lower of the
two endpoints' final blocks, which the other endpoint must report with the same hash at that height, the two final heights at most
20 blocks apart. Each `is_spent` is then read from both endpoints at that block, and a disagreement is an error that decides
nothing. With one endpoint only, that endpoint is trusted: a lying endpoint could make a spent note look unspent
(it is then held again after its deadline, and the contract refuses it if used) or an unspent note look spent (it is then marked
spent, and its value is lost to the wallet). `is_spent` names a nullifier to the endpoint: a spent nullifier is public anyway;
asking about one that is not spent yet tells the endpoint something about a later spend.

## What happens to the notes

Each note has a fresh owner key. Its secrets are saved in the encrypted wallet before its blinded point leaves the computer. Before
an owner signature leaves, the note is marked `spending`, with the signature's deadline. Then:

- the agent reports success: the note is `spent` and the new notes are kept;
- the agent reports a certain refusal (nothing sent, or refused by the chain): the note is `held` again, and the new notes made
  for the operation are forgotten;
- the outcome is unknown (sent, no answer): the note stays `spending` and its new notes stay `awaiting_signature`, until
  `pool_recover` finds out.

The wallet keeps every note and its status across restarts. Owner signatures follow `SPEC.md` (`ona-pool`: ENTER-V1, LEAVE-V1,
CASH-EXIT-V1) and expire 24 hours after they are made, so the agent can batch them.

A switch and an exit first turn each share note into cash notes (a leave), which the contract pays only from the vault's liquid
funds: if the vault's money is staked, the agent keeps the leave queued until it has brought funds back (the contract lets it
unstake once per vault every 3 days, so this can take days).

## Example run

From `examples_for_the_docs` in `crates/ona-core/tests/pool.rs` (fake pool: cash notes of 0.1, 1 and 10 NEAR; share notes of 0.01,
0.1 and 1 NEAR at the initial price; recommended deposits set to 10 and 11 NEAR). Lines starting with `>` are requests, `<`
replies. The `prepared_id`s, hashes and signatures are shortened, and repeated steps are cut (`…`). The fake agent of this test
answers at once; with the real agent, every `pool_execute` after the deposit answers `outcome unknown` and its result comes
through a later `pool_recover`, the switch stopping after its leave.

```
> {"account":"alice.test","amount":"11000000000000000000000000","cmd":"pool_prepare","op":"deposit"}
< {"mode":"mock","ok":true,"prepared_id":"6ac37446…220a4d","summary":{"account":"alice.test","amount":"11000000000000000000000000","cash_notes":[{"count":1,"note_value":"1000000000000000000000000","tier":1},{"count":1,"note_value":"10000000000000000000000000","tier":2}],"contract":"pool.test","expires_at":1000000300000000000,"fees":{"refundable":"unused margin","storage_margin":"10000000000000000000000"},"network":"sandbox","op":"deposit","recommended":["10000000000000000000000000","11000000000000000000000000"],"wallet_call":{"args":{},"attached":"11010000000000000000000000","method":"deposit","receiver":"pool.test"}}}

> {"cmd":"pool_execute","prepared_id":"6ac37446…220a4d"}
< {"complete":false,"executed":"deposit","mode":"mock","next":"sign sign_message with the depositing account's wallet (NEP-413), then call pool_execute again with depositor_signature","ok":true,"sign_message":{"message":"ONA pool cash issue v1\npool: pool.test\naccount: alice.test\nnotes: e24e28bb…fe7d80","nonce":"ryrsTwuj…","recipient":"pool.test"}}

> {"cmd":"pool_execute","depositor_signature":{"public_key":"ed25519:US517G59…","signature":"CAgICAgI…"},"prepared_id":"6ac37446…220a4d"}
< {"complete":true,"executed":"deposit","mode":"mock","ok":true,"steps":[{"issued_cash":2}]}

> {"amount":"10000000000000000000000000","cmd":"pool_prepare","op":"enter","vault":0}
< {"mode":"mock","ok":true,"prepared_id":"57a0c3eb…3f2965","summary":{"amount":"10000000000000000000000000","contract":"pool.test","expires_at":1000000300000000000,"fees":{"storage":"2000000000000000000000"},"left_in_cash":"8000000000000000000000","network":"sandbox","op":"enter","shares_value":"9990000000000000000000000","vault":0}}

> {"cmd":"pool_execute","prepared_id":"57a0c3eb…3f2965"}
< {"complete":true,"executed":"enter","mode":"mock","ok":true,"steps":[{"entered":0}]}

> {"cmd":"pool_portfolio"}
< {"cash":{"awaiting_signature":0,"spending_value":"0","tiers":[{"held":1,"note_value":"1000000000000000000000000","spending":0,"tier":1}],"value":"1000000000000000000000000"},"mode":"mock","ok":true,"total":"10990000000000000000000000","vault_count":2,"vaults":[{"awaiting_signature":0,"frozen":false,"share_price":"1000000000000000000","spending_value":"0","tiers":[{"held":9,"note_value":"10000000000000000000000","spending":0,"tier":0},{"held":9,"note_value":"100000000000000000000000","spending":0,"tier":1},{"held":9,"note_value":"1000000000000000000000000","spending":0,"tier":2}],"value":"9990000000000000000000000","vault":0}]}

> {"amount":"1000000000000000000000000","cmd":"pool_prepare","from":0,"op":"switch","to":1}
< {"mode":"mock","ok":true,"prepared_id":"7391e18f…222bf5","summary":{"amount":"1000000000000000000000000","contract":"pool.test","expires_at":1000000300000000000,"fees":{"storage":"20000000000000000000000"},"from":0,"left_in_cash":"170000000000000000000000","network":"sandbox","new_shares_value":"810000000000000000000000","op":"switch","share_price":"1000000000000000000","to":1}}

> {"cmd":"pool_execute","prepared_id":"7391e18f…222bf5"}
< {"complete":true,"executed":"switch","mode":"mock","ok":true,"steps":[{"cash_notes":9,"left":0},{"entered":1},…,{"entered":1}]}

> {"amount":"1000000000000000000000000","cmd":"pool_prepare","from":0,"op":"exit"}
< {"mode":"mock","ok":true,"prepared_id":"28988c6f…afa2d6","summary":{"amount":"1000000000000000000000000","cash_value":"900000000000000000000000","contract":"pool.test","expires_at":1000000300000000000,"fees":{"storage":"2000000000000000000000"},"from":0,"left_in_cash":"98000000000000000000000","network":"sandbox","op":"exit","share_price":"1000000000000000000"}}

> {"cmd":"pool_execute","prepared_id":"28988c6f…afa2d6"}
< {"complete":true,"executed":"exit","mode":"mock","ok":true,"steps":[{"cash_notes":9,"left":0}]}

> {"amount":"1900000000000000000000000","cmd":"pool_prepare","op":"exit_cash","to":"alice.test"}
< {"mode":"mock","ok":true,"prepared_id":"41a8019c…b9e0d8","summary":{"amount":"1900000000000000000000000","contract":"pool.test","exit_limit":"11010000000000000000000000","expires_at":1000000300000000000,"fees":{"storage":"20000000000000000000000"},"network":"sandbox","op":"exit_cash","received":"1880000000000000000000000","to":"alice.test"}}

> {"cmd":"pool_execute","prepared_id":"41a8019c…b9e0d8"}
< {"complete":true,"executed":"exit_cash","mode":"mock","ok":true,"steps":[{"paid":1,"to":"alice.test"},…,{"paid":1,"to":"alice.test"}]}

> {"cmd":"pool_recover"}
< {"awaiting_signature":0,"held_again":0,"mode":"mock","ok":true,"signatures_recovered":0,"spent":0,"still_spending":0}
```

In this example the switch leaves 0.17 NEAR in the cash out of 1 NEAR: with these coarse test tiers each 0.1-NEAR cash note buys
only nine 0.01-NEAR shares. Finer tiers lose less; the app should show `left_in_cash` before the user confirms.

## Errors

Every error is `{"ok":false,"error":"…","mode":…}`. Among them: `no pool wallet configured`, `no connection to the pool agent yet`,
`outcome unknown, run pool_recover later: …`, `unknown, expired or already used prepared_id`,
`below the contract's smallest deposit (0.1 NEAR)`, `the amount is not a sum of whole notes: …`,
`the amount is not a sum of cash notes`, `over this account's exit limit (…)`, `no vault N`, `this vault is frozen`,
`choose another vault`, `to: …` (not a NEAR account), `unknown operation …`, `a value read from the pool is too large`, and the
agent's or the contract's refusal.
