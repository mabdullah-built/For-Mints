# `kairox watch`

Waits for an explicitly-configured, not-yet-open SeaDrop/OpenSea stage to
become active, then executes automatically at the earliest valid moment --
without the operator manually re-running `inspect`/`plan`/`mint` around T0.

`watch` never discovers a collection or wallet on its own. It only ever acts
on the single `<collection> --wallet ...` pair given on the command line, or
on entries explicitly listed in a `--manifest` file. It requires
`--auto-send`: since nothing is present to answer an interactive
confirmation prompt hours or days later, `watch` refuses to run at all
without this explicit upfront consent.

```
kairox watch <collection> --wallet <wallet> [--slug <slug>] --quantity 1 --auto-send
kairox watch --manifest watchlist.toml --auto-send
```

## What's actually new here

The T-10s/T-3s/T-1s/T0 critical path (nonce/fee/balance/supply reads,
signing, serialization, identical-raw-transaction fan-out, receipt
verification) is not reimplemented by `watch` -- it calls the exact same
`run_live_mint`/`run_opensea_mint` engines `kairox mint --send` uses, both of
which already accept a stage start arbitrarily far in the future and already
sleep correctly to it.

The one new piece is the long-horizon **WAITING** loop
(`execution::watch::wait_for_stage`): while the best-known stage start is
still far away, `watch` periodically re-verifies stage timing, supply, and
(for the PUBLIC engine) wallet allocation -- so a sold-out collection, a
rescheduled stage, or an exhausted allocation is caught during the wait
instead of only being discovered in the final seconds. Once the stage start
is within the engine's own `state_check_lead` (10s by default), `watch`
stops polling and hands off to the unmodified engine.

## States

`DISCOVER` → `VERIFY` → `WAITING` (recurs while far from T0) → `TMinus10` →
`TMinus3` → `Arming` → `Armed` → `T0` → `Broadcasting` → `Receipt` →
`SUCCESS` | `STOPPED`.

A stage that starts in the future is never an error -- `WAITING` is the
expected, normal state for it. `STOPPED` conditions (fail-closed, no
retry/replacement): wrong chain, stage ended, sold out, wallet allocation
exhausted, insufficient balance, a fee/spend cap exceeded, an invalid
OpenSea response, an invalid Merkle proof, an unauthorized server signer, or
an uncertain broadcast.

## Watchlist (`--manifest`) schema

```toml
[[target]]
chain = "robinhood chain"        # optional; same precedence as --chain
collection = "0x..."
wallet = "0x..."
slug = "optional-opensea-slug"
quantity = 1
engine = "auto"                  # "auto" | "public" | "opensea"
fee_recipient = "0x..."          # optional
max_mint_value_wei = "0"
max_gas_cost_wei = "1000000000000000000"
max_total_spend_wei = "1000000000000000000"
gas_buffer_multiplier = 1.25

[[target]]
collection = "0x..."
wallet = "0x..."
```

Every `[[target]]` entry runs concurrently and independently -- own chain
connection, own signing-key/wallet check, own stage state. `watch` never
adds a target that isn't explicitly listed here or passed on the command
line.

## Remaining limitations

- No `--json`/`--output` structured report yet (text/stderr progress only);
  the final broadcast/receipt result reuses `mint`'s existing text report.
- The signing key is loaded once at watch start (immediately after VERIFY,
  before any waiting) and held in process memory for the full wait, the same
  trust model an unattended process already implies elsewhere in Kairox --
  there is no separate encrypted-at-rest key store.
- A `NotStarted` on-chain public stage and an OpenSea `next_stage` are both
  legitimate future targets. `--engine auto` (the default) no longer
  requires `--slug`: an upcoming, currently-recognized *non-public*
  OpenSea stage (signed-presale/allowlist/FCFS/FCFA) is auto-discovered
  and preferred over a later on-chain public stage — see
  `docs/resolver-architecture.md`'s tier-0 `OpenSeaDropsAdapter` section.
  A collection with neither a configured on-chain public stage nor any
  discoverable/explicit OpenSea drop is still rejected outright (never
  guessed).
- If the fresh, wallet-specific OpenSea authorization requested at T0
  comes back with a genuine ineligibility rejection, `watch` stops that
  target's session rather than automatically re-resolving to a later
  supported stage (e.g. a public stage opening after the presale). This
  is a known, disclosed limitation, not yet implemented.
