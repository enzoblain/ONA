# Countermeasures against the user to vault leak

Simulated only, 2026-11-11, with `ona-crowd parades` and `ona-crowd yield`. Nothing here has run on a chain.

Exits go back only to the account that deposited, so amounts in and out are public. What should stay private is which vault each
user chose and when the agent placed for them.

## Options (agent and configuration, all off by default)

| Option | Effect |
|---|---|
| `reserve_percent` | Part of each batch stays liquid. Exits are paid from this reserve, refilled from the fullest vault when short. |
| `settlement_period_secs` | Funds move between the reserve and the vaults only at multiples of this period, the net difference per vault. Rewards are credited at the same moments. |
| `min_active_per_settlement` | A settlement waits until this many requests were placed or left since the last one. |
| `noise_moves_per_hour` | One-note round trips between two vaults, unrelated to requests. Four agent transactions each. |
| `steady_withdrawal_period_secs`, `_units` | A fixed amount leaves every vault at a fixed pace; the next settlement puts back what is not needed. Needs settlement. |
| `switch_percent` | Share of users moving to another vault while placed, folded into the next settlement. Needs settlement. |
| `yield_bp_per_hour`, `yield_mode` | Rate per vault; gain at the user's vault rate (`individual`) or the pool's average (`pooled`), paid later in whole notes. |
| `vault_weights`, `suggestion_percent` | Popularity of each vault; share of users who accept moving to the most popular vault of the same kind. |

"Separate accounting" below is reserve 20 %, settlement every 1,800 s and at least 10 active requests per settlement.

## The measures

- **Vault certain (bound)**: vaults the public timeline and rules eliminate; without countermeasures, batches are also assigned
  jointly. Sound, incomplete: an **upper bound on privacy**. `*` = per-account check only, weaker still.
- **Entropy, observer finds**: from assignments sampled by Markov chain Monte Carlo (after Troncoso and Danezis, CCS 2009). Four chains,
  each started from the true assignment, half their steps discarded. A step swaps the routes of two accounts of the same class: same
  deposits and payments; with net settlement, the same settlements absorbing their placement and their exit (the first settlement
  that actually ran at or after each); with yield outside direct exits, the same placement and exit moments. Accounts that switched
  vault are not moved. **Every recorded state is replayed** (batch contents, amounts taken out of each batch, what each vault owes at
  each settlement, rewards per vault) and must match the truth. A test checks it over every scenario, with and without settlement
  and yield. The 50-user runs below (varied amounts and yield) printed 0 failures; the 500-user and uniform runs were made before
  the binary printed the count.
- **Frozen users**: placed users no other account matches, so the sampler never moves them. Their vault always comes out certain: **a
  limit of the sampler, not a finding**. Every table has frozen users, so the probability of guessing the worst-off user is 100 %
  everywhere and is not shown. Exchanges of unequal accounts (one deposit of 110 against 100 + 10) are not tried, and the chains start
  from the truth: the observer looks more certain than a perfect one would, so these figures err on the side of less privacy.
- **Last-withdrawal guess**: the vault of the last withdrawal before a user's first payment. With two vaults, a figure far below blind
  leaks as much as one far above (guess the other vault).
- **Reward-credit guess**: the vault whose public reward credit is closest in time to the user's first payment.
- **Rate guess**: (everything paid back minus everything deposited) / deposit / time, less the delays the rules impose, matched to the
  nearest vault rate. Full exits only.
- **Yield given up**: share of the gain at the rate of the vault first wanted that the user does not get (suggestion, or pooling).
- **Blind**: share of the most chosen vault. **Agent tx**: moves grouped per vault and moment, plus one per payment.

## Results, 2 vaults, 6 simulated hours, seeds 1 to 10

Defaults otherwise: k = 5, wait 300 s, stay 900 to 3,600 s, notes of 1, 10 and 100 (1, 2 or 4 of each), 30 % partial exits.

50 users:

| Countermeasure | Vault certain (bound) | Frozen users | Entropy | Observer finds | Blind | Last-withdrawal guess | Agent tx | Extra tx | Paid out |
|---|---|---|---|---|---|---|---|---|---|
| none | 92 % | 57 % | 0.01 bit | 100 % | 57 % | 91 % | 156 | +0 | 87 % |
| reserve 20% | 9 % * | 57 % | 0.08 bit | 97 % | 57 % | 35 % | 154 | -3 | 87 % |
| net settlement every 1800 s | 0 % * | 83 % | 0.08 bit | 98 % | 57 % | 17 % | 148 | -8 | 87 % |
| noise 12/h | 72 % * | 57 % | 0.01 bit | 99 % | 57 % | 85 % | 424 | +267 | 85 % |
| reserve + settlement + noise | 0 % * | 80 % | 0.11 bit | 94 % | 57 % | 51 % | 404 | +248 | 87 % |
| separate accounting | 0 % * | 83 % | 0.08 bit | 98 % | 57 % | 17 % | 148 | -8 | 87 % |
| separate accounting + steady withdrawals | 0 % * | 83 % | 0.08 bit | 98 % | 57 % | 46 % | 211 | +54 | 87 % |
| separate accounting + 30% switch | 0 % * | 85 % | 0.09 bit | 95 % | 58 % | 16 % | 144 | -13 | 84 % |

500 users:

| Countermeasure | Vault certain (bound) | Frozen users | Entropy | Observer finds | Blind | Last-withdrawal guess | Agent tx | Extra tx | Paid out |
|---|---|---|---|---|---|---|---|---|---|
| none | 43 % | 11 % | 0.04 bit | 98 % | 53 % | 72 % | 1682 | +0 | 99 % |
| reserve 20% | 0 % * | 11 % | 0.43 bit | 81 % | 53 % | 38 % | 1654 | -27 | 99 % |
| net settlement every 1800 s | 0 % * | 32 % | 0.50 bit | 79 % | 53 % | 21 % | 1635 | -47 | 99 % |
| noise 12/h | 38 % * | 12 % | 0.04 bit | 98 % | 53 % | 66 % | 1957 | +275 | 99 % |
| reserve + settlement + noise | 0 % * | 32 % | 0.50 bit | 79 % | 53 % | 47 % | 1891 | +209 | 99 % |
| separate accounting | 0 % * | 32 % | 0.50 bit | 79 % | 53 % | 21 % | 1634 | -47 | 99 % |
| separate accounting + steady withdrawals | 0 % * | 32 % | 0.50 bit | 79 % | 53 % | 43 % | 1696 | +15 | 99 % |
| separate accounting + 30% switch | 0 % * | 56 % | 0.31 bit | 87 % | 53 % | 22 % | 1620 | -61 | 99 % |

50 users, every deposit one note of 100, full exits (uniform amounts):

| Countermeasure | Vault certain (bound) | Frozen users | Entropy | Observer finds | Blind | Last-withdrawal guess | Agent tx | Extra tx | Paid out |
|---|---|---|---|---|---|---|---|---|---|
| none | 73 % | 0 % | 0.18 bit | 93 % | 56 % | 86 % | 56 | +0 | 85 % |
| reserve 20% | 10 % * | 0 % | 0.80 bit | 60 % | 56 % | 37 % | 55 | -1 | 85 % |
| net settlement every 1800 s | 0 % * | 2 % | 0.86 bit | 61 % | 56 % | 24 % | 48 | -8 | 85 % |
| noise 12/h | 18 % * | 0 % | 0.23 bit | 88 % | 57 % | 62 % | 326 | +270 | 85 % |
| reserve + settlement + noise | 0 % * | 1 % | 0.81 bit | 66 % | 55 % | 46 % | 264 | +208 | 83 % |
| separate accounting | 0 % * | 2 % | 0.86 bit | 61 % | 56 % | 24 % | 48 | -8 | 85 % |
| separate accounting + steady withdrawals | 0 % * | 2 % | 0.86 bit | 61 % | 56 % | 24 % | 48 | -8 | 85 % |
| separate accounting + 30% switch | 0 % * | 31 % | 0.60 bit | 75 % | 56 % | 23 % | 51 | -5 | 90 % |

Steady withdrawals of 10 units do nothing here: notes of 100 cannot carry 10. Switching freezes the users who switch (31 % here), which
lowers the measured entropy: an effect of the sampler, not evidence that switching hurts.

## Yield, 4 vaults (2 staking, 2 lending), separate accounting, full exits, seeds 1 to 10

Weights 3, 1, 3, 1; rates 100, 200, 300 and 600 basis points **per hour**, that is 1 to 6 % per hour. These are accelerated so gains
show within a 6-hour demo; they are not realistic rates. The most popular vault of each kind is also the lower-paying one, so a
suggestion costs yield. Rewards are credited per vault at each settlement.

50 users:

| Option | Frozen users | Observer finds | Blind | Last-withdrawal guess | Reward-credit guess | Rate guess | Yield given up | Agent tx | Extra tx | Paid out |
|---|---|---|---|---|---|---|---|---|---|---|
| no yield | 72 % | 92 % | 44 % | 12 % | - | - | - | 157 | +0 | 77 % |
| pooled yield | 92 % | 100 % | 44 % | 14 % | 41 % | 33 % | 23 % | 210 | +54 | 76 % |
| individual yield, 0% follow suggestions | 91 % | 100 % | 44 % | 13 % | 40 % | 51 % | 0 % | 202 | +45 | 76 % |
| individual yield, 30% follow suggestions | 95 % | 100 % | 51 % | 19 % | 46 % | 60 % | 5 % | 207 | +50 | 74 % |
| individual yield, 60% follow suggestions | 95 % | 100 % | 55 % | 24 % | 43 % | 60 % | 13 % | 205 | +48 | 75 % |

500 users:

| Option | Frozen users | Observer finds | Blind | Last-withdrawal guess | Reward-credit guess | Rate guess | Yield given up | Agent tx | Extra tx | Paid out |
|---|---|---|---|---|---|---|---|---|---|---|
| no yield | 16 % | 62 % | 39 % | 6 % | - | - | - | 1865 | +0 | 98 % |
| pooled yield | 93 % | 100 % | 39 % | 6 % | 35 % | 30 % | 27 % | 2604 | +739 | 98 % |
| individual yield, 0% follow suggestions | 94 % | 100 % | 39 % | 7 % | 35 % | 54 % | 0 % | 2472 | +608 | 98 % |
| individual yield, 30% follow suggestions | 92 % | 100 % | 44 % | 4 % | 42 % | 58 % | 7 % | 2478 | +613 | 98 % |
| individual yield, 60% follow suggestions | 92 % | 100 % | 47 % | 5 % | 47 % | 60 % | 14 % | 2443 | +578 | 98 % |

With yield the sampler must keep exact placement and exit moments, so almost every user is frozen and the sampled measure says
nothing (entropy 0): **for yield, only the guesses are informative.**

## What this suggests

1. **Varied amounts appear to be the main leak.** With varied deposits the sampled observer finds 79 to 100 % of vaults; with one
   fixed deposit size, separate accounting brings it to about 61 % against 56 % blind. For an observer who sees only amounts and
   settlements, both figures overstate what it finds (frozen users, swaps of equal accounts only); an observer who also uses timing
   can do better (see 2). The gap between the two settings matters more than either figure.
2. **Separate accounting removes certainty but not timing.** Under net settlement the last withdrawal before a payment points away
   from the user's vault (17 to 24 % with two vaults, about 80 % by guessing the other). Steady withdrawals or noise bring it near
   50 %; steady withdrawals cost far less (+15 to +54 transactions per 6 hours against +200 to +270 for noise).
3. **Individual yield leaks through the rate, at these accelerated rates.** The rate guess finds 51 to 54 % against 39 to 44 % blind.
   With real rates, gains over a few hours are far smaller and mostly below one note, so this leak is likely weaker but also
   unmeasured. Pooled yield hides the rate (guess below blind) but moves 23 to 27 % of the gain between users. Rewards credited per
   vault at each settlement give little: the reward-credit guess stays near or below blind. Gains smaller than the smallest note
   cannot be paid in whole notes; here they stay in the pool.
4. **Suggestions do not help in this measure.** They raise blind guessing as much as the observer's success and cost 5 to 14 % of the
   yield.
5. **Some users are never moved by the sampler** (frozen, 11 to 95 % depending on the setting), so no row shows a worst-off user
   below 100 %. This says the sampler is limited, not that these users are certainly exposed.

## Not done or not measured

- Exchanges of unequal accounts, chains not started from the truth, and an exact count on small cases are not done.
- The sampled measure ignores timing and rates beyond its classes; the guesses cover them separately, and no measure combines them.
- With pooled yield and net settlement, gains depend on what each vault holds between settlements, which the replay does not cover.
- More than four vaults, other periods, realistic rates and gas costs are untested. Nothing ran on a chain.

Reproduce with `cargo run --release -p ona-crowd -- parades crowd.json 10` or `-- yield crowd.json 10`. `crowd.json` sets `users`,
`run_secs` (21600 here), the vaults and, for `yield`, `yield_bp_per_hour`, `vault_weights` and `partial_exit_percent: 0`. The
500-user yield run takes about ten minutes.
