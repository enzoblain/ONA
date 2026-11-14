# Privacy figures (`pool_privacy`)

The figures the apps show in the Pool window, next to the portfolio and next to each vault offered for an entry. They
come from `ona-core`'s `pool_privacy` command and are counted on the chain at the moment they are read: no fixed or
invented percentage (README, "Next steps").

## The measure

- **A note's set**: the notes **still in circulation** of the same value at the same place (the cash, or one vault),
  that is `issued - paid` of its tier as the contract's `get_cash` and `get_vault` views publish them. An observer of the
  chain cannot tell the note from the others of that set.
- **The wallet's figure** (`wallet.smallest_set`): the smallest set among its held notes, its weakest note.
- **For an entry** (`vaults[i].if_entered`): the smallest set the share notes of that entry would join (its amount split
  into the vault's share tiers, each set counting the new note), for the held cash or a given `amount`.
  `vaults[i].gain`: that set minus the cash's smallest set. This is the "+ X" next to a vault: X more notes to hide among
  than the cash spent.
- **Without ONA** (`without_ona`): 1. A deposit straight into staking is tied to its account.

The apps say it in words ("blends in with at most N notes"), never as a percentage. When the set is 1, the panel says
the note can be followed.

## What it does not measure

These are **upper bounds**. An observer who also uses deposit and exit times, amounts and the agent's batches can rule some
notes out: `crates/ona-crowd` measures that on simulated crowds. The count also says nothing about the IP addresses and
timing seen by the RPC nodes and the agent (the apps send these through Tor).

## Tested

- `privacy_counts_the_notes_a_note_hides_among` (`crates/ona-core/tests/pool.rs`), on the fake pool with chosen counts.
- The apps: Swift tests of the sentences; the Tauri window read against a fake bridge.
- On a local node (`ona-sandbox-pool --serve`, 13/11/2026), through the Tauri engine: the 10 NEAR note of the only depositor
  was alone in its set (1), its two 1 NEAR notes in a set of 2.
