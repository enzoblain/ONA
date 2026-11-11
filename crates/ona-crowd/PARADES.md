# Countermeasures against the user to vault leak

Simulated only, 2026-11-11, with `ona-crowd parades`. Nothing here has run on a chain.

Exits go back to the account that deposited, so amounts in and out are public. What should stay private is which vault each user
chose. Without countermeasures it mostly does not: each placement follows a batch of requests, and each vault withdrawal precedes
precise exits.

## Countermeasures (agent options, all off by default)

| Option | Effect |
|---|---|
| `reserve_percent` | The agent places only part of each batch and keeps the rest liquid. Exits are paid from this reserve, refilled from the fullest vault when it runs short. |
| `settlement_period_secs` | The agent moves funds between the reserve and the vaults only at multiples of this period, and only the net difference per vault, in fixed notes. |
| `noise_moves_per_hour` | One-note round trips between two vaults, unrelated to any request. Each costs four agent transactions. |

## Results

Defaults otherwise (k = 5, wait 300 s, stay 900 to 3,600 s, notes of 1, 10 and 100), 2 vaults, 6 simulated hours, seeds 1 to 10,
reserve 20 %, settlement every 1,800 s, noise 12 round trips per hour.

50 users:

| Countermeasure | Vault certain | Possible vaults, median / min | First-placement guess | Last-withdrawal guess | Blind guess | Agent tx per run | Extra tx | Paid out |
|---|---|---|---|---|---|---|---|---|
| none | 92 % | 1 / 1 | 58 % | 91 % | 57 % | 156 | +0 | 87 % |
| reserve 20% | 9 % * | 2 / 1 | 58 % | 35 % | 57 % | 154 | -3 | 87 % |
| net settlement every 1800 s | 0 % * | 2 / 2 | 48 % | 17 % | 57 % | 148 | -8 | 87 % |
| noise 12/h | 72 % * | 1 / 1 | 55 % | 85 % | 57 % | 424 | +267 | 85 % |
| reserve + settlement | 0 % * | 2 / 2 | 48 % | 17 % | 57 % | 148 | -8 | 87 % |
| reserve + settlement + noise | 0 % * | 2 / 2 | 51 % | 51 % | 57 % | 404 | +248 | 87 % |

200 users:

| Countermeasure | Vault certain | Possible vaults, median / min | First-placement guess | Last-withdrawal guess | Blind guess | Agent tx per run | Extra tx | Paid out |
|---|---|---|---|---|---|---|---|---|
| none | 66 % | 1 / 1 | 49 % | 77 % | 53 % | 678 | +0 | 97 % |
| reserve 20% | 0 % * | 2 / 1 | 49 % | 37 % | 53 % | 663 | -15 | 97 % |
| net settlement every 1800 s | 0 % * | 2 / 2 | 43 % | 20 % | 53 % | 648 | -30 | 97 % |
| noise 12/h | 53 % * | 1 / 1 | 50 % | 70 % | 53 % | 950 | +272 | 98 % |
| reserve + settlement | 0 % * | 2 / 2 | 43 % | 20 % | 53 % | 648 | -30 | 97 % |
| reserve + settlement + noise | 0 % * | 2 / 2 | 50 % | 47 % | 53 % | 902 | +224 | 98 % |

## How to read it

- **Vault certain** and **possible vaults** come from eliminating every vault that the public timeline and the public rules
  rule out. Without countermeasures, batches are also assigned jointly: a batch holds exactly the notes of its members, so two
  accounts that alone hold notes of 1 are forced into the batch that has them, which pushes the others out. This is sound (the
  true vault is never removed, checked by a test over every scenario) but not complete: **these figures are an upper bound on
  privacy**, a stronger observer can do better. Rows marked * use only the per-account check, which is weaker still.
- **Guesses** are two timing attacks scored against the ground truth: the vault of the first placement after the deposit, and the
  vault of the last withdrawal before the first exit. **With two vaults, an accuracy far below the blind guess leaks as much as one
  far above**: guessing the other vault gives 100 % minus the figure. The last-withdrawal guess at 17 to 20 % under net settlement
  therefore finds the vault of about 80 % of users, although no vault is certain.
- **Agent tx** counts placements and withdrawals grouped per vault and moment, plus one per exit payment. Gas per transaction is
  not measured for staking calls, so no cost in NEAR is given. Netting saves a few transactions; noise costs about four per round
  trip.

## What this changes

- Without countermeasures, the vault of most users can be deduced: 92 % with 50 users, 66 % with 200.
- Net settlement alone removes certainty, by the weaker per-account check only; a reserve alone leaves 9 % of vaults certain with
  50 users (0 % with 200). Neither removes the timing leak. Only the three together bring both guesses near
  the blind guess, at about +250 agent transactions per 6 hours.
- Not tested: more than two vaults, other periods and reserve sizes, yield differing between vaults, and an observer combining
  several runs or using probabilities. The last two are the next step (a Bayesian measure).

Reproduce with `cargo run --release -p ona-crowd -- parades crowd.json 10`, where `crowd.json` sets `users`, `run_secs` (21600 here)
and the two vaults. Options already set in its `agent` section are used for the scenarios; otherwise 20 %, 1,800 s and 12 per hour.
