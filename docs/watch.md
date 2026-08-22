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

For an already-open stage, use `kairox mint <collection> --send --yes`
instead -- `watch` is specifically for a stage that has not opened yet.

## Architecture

### Early pool lifetime

Unlike an earlier version of this code, the RPC send pool is connected and
put through a full, multi-sample benchmark **before** `watch` starts waiting
-- not after. Concretely, `run_public_watch`/`run_opensea_watch` each:

1. `connect_send_pool` -- one `RpcPool`, chain-id-verified.
2. `pool.benchmark_all(&profile.benchmark_policy)` -- the full, multi-sample
   ranking pass (e.g. 4-6 samples per read-capable endpoint depending on the
   chain profile), establishing which endpoint is fastest well ahead of
   time.
3. `pool.rewarm_all()` -- an immediate liveness check on top of that.

Only then does `wait_for_stage` (the WAITING loop, below) begin. That same
`RpcPool` instance stays alive across the entire wait and straight into
dispatch -- it is never reconnected or re-benchmarked from scratch at T0.
The one exception: a full re-resolution restart (see below) is a genuinely
new attempt against a possibly-different stage, and connects its own fresh
pool, deliberately -- there is no reason to trust the previous attempt's
now-irrelevant ranking data for a different target.

### Near-T0 liveness without re-ranking

Right before dispatch, `run_live_mint`/`run_opensea_mint` always take one
more liveness sample (`RpcPool::rewarm_all`) so a formerly-fastest endpoint
that has since died is never selected on stale data -- `rewarm_all` marks a
now-failing endpoint unhealthy immediately, and endpoint selection always
filters on health *before* consulting ranking data. What they do *not* do,
when `watch` already ran the full benchmark above, is repeat a full
multi-sample ranking pass -- that would silently discard the good ranking
data gathered minutes or hours earlier in favor of one noisy last-moment
sample. This is `LiveMintConfig::skip_benchmark`/`OpenSeaMintRequest::skip_benchmark`,
set by `watch` and only by `watch`.

### WAITING loop

The long-horizon **WAITING** loop (`execution::watch::wait_for_stage`,
unmodified by any of the above) polls at the configured `--poll-interval-secs`
while the best-known stage start is still far away. Once the stage start is
within the engine's own `state_check_lead` (10s by default), `watch` stops
polling and hands off to the unmodified engine -- the T-10s/T-3s/T-1s/T0
critical path itself is not reimplemented by `watch`; it calls the exact
same `run_live_mint`/`run_opensea_mint` engines `kairox mint --send` uses.

### Periodic re-resolution (`--engine auto` only)

A long wait does not remain permanently committed to whatever
`--engine auto` picked before the wait began. Every 30 seconds (fixed;
not operator-configurable), a background check re-runs full resolution
and compares it against the stage/engine this attempt started with. If
they disagree -- a creator-changed start time revealing a different
winner, a newly-published earlier stage, a changed stage identity, or
OpenSea recovering from an outage -- the current attempt is abandoned and
a fresh one starts against the new resolution (fresh pool, fresh
benchmark, fresh wait). This restart is bounded (at most 20 times per
watch invocation) and is never triggered by, or counted against, a wallet
-eligibility rejection -- those are a separate, independently-bounded
retry path (below). An operator-forced `--engine public`/`--engine
opensea` target has nothing ambiguous to re-check, so this adds no extra
traffic at all in that case.

### Re-resolution after a clear ineligibility rejection

If the *fresh*, wallet-specific OpenSea authorization requested at (or
near) T0 comes back with an unambiguous `422` eligibility rejection for
that exact stage, `watch` excludes that stage's own unique identity (its
OpenSea stage UUID -- never the wider collection slug, which can span
several distinct stages) and re-resolves, so a later legitimately
-supported stage (a second signed stage, or a public stage opening after
a presale) still gets a real chance instead of the whole session
aborting. Bounded to 4 attempts. A transport error, rate limit, timeout,
server error, allocation-exceeded, or supply-exhausted outcome is
*never* treated as an ineligibility rejection -- only that one specific,
unambiguous classification triggers exclusion.

### Advisory telemetry

While waiting, `watch` opportunistically records bounded, in-memory,
session-scoped telemetry: per-probe latency/outcome history, and (using
the same already-connected send pool, one extra read-only
`eth_getBlockByNumber` + best-effort `eth_maxPriorityFeePerGas` call per
poll cycle) the latest observed block number/timestamp/base fee/priority
fee. Every value is exposed with explicit freshness (`Fresh`/`Stale`
-with-age/`Unavailable`, a 10-second TTL) rather than a bare number. None
of this is ever consulted by any signing or spend-authorization decision
-- it exists purely for the one summary printed to stderr *after*
dispatch and receipt confirmation complete, never before or during. See
`chain::telemetry`'s module docs for the full architecture and its
mandatory-fresh-check invariant.

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

## T0 critical-path trace

Everything below "stage detected active" runs with no *blocking*
optional work interleaved -- no telemetry formatting, no full benchmark,
no unrelated discovery, no disk I/O, no synchronous terminal write
between activation and dispatch. `M` = mandatory (synchronous). `O-NB` =
optional, non-blocking (a `ProgressReporter::emit` -- a `try_send`,
proven never to await or block regardless of consumer state; see
`cli::progress_reporter`'s tests). `O` = optional, synchronous -- there
are none left in this interval; every progress print between handoff and
dispatch now goes through the non-blocking reporter.

### PUBLIC engine

| Point | Operation | M/O |
|---|---|---|
| T-early (pre-wait) | Connect send pool, verify chain id | M |
| T-early | Full multi-sample benchmark (`benchmark_all`) | M (once) |
| T-early | Immediate rewarm | M |
| T-early..T-10 | WAITING poll loop (own connection, `build_mint_plan`) | M |
| T-early..T-10 | Advisory telemetry recording (latency, block/fee) | O-NB -- `try_lock`, gated off entirely once close to T0 |
| handoff | `reporter.emit(Arming)` | O-NB |
| T-10 (StateCheck) | Fresh `getPublicDrop` read, end-time check | M |
| T-10..T0 | Checkpoint/waiting progress events | O-NB |
| T-6 (Refresh) | Fresh nonce/fee/balance/gas-estimate read, re-sign | M |
| T-1 (Finalize) | Fresh nonce/fee/balance/gas-estimate read, re-sign | M |
| T0 | Near-T0 rewarm (liveness only, no re-ranking) | M |
| T0 | Endpoint selection (health-filtered, already-ranked) | M |
| T0 | `eth_sendRawTransaction` fan-out (identical raw bytes, every selected endpoint) -- skipped under `--rehearsal` | M |
| after dispatch | Receipt polling (skipped under `--rehearsal`) | M |
| after dispatch | `reporter.emit(Success)`, then a single bounded (≤500ms) `reporter.finish().await` flush | O-NB, then a one-time bounded wait -- never on the path above |
| after dispatch | Telemetry summary printed | O -- explicitly *after* this point and after the flush, never before |

### OPENSEA (signed) engine

| Point | Operation | M/O |
|---|---|---|
| T-early (pre-wait) | Connect send pool, verify chain id | M |
| T-early | Full multi-sample benchmark (`benchmark_all`) | M (once) |
| T-early | Immediate rewarm | M |
| T-early..T-10 | WAITING poll loop (OpenSea drop-details polling, real, already-warm client) | M |
| T-early..T-10 | Advisory telemetry recording | O-NB |
| handoff | `reporter.emit(Arming)` | O-NB |
| fresh authorization point (at/near activation) | `POST /drops/{slug}/mint` -- wallet-specific authorization, bounded retries, classified (inactive/ineligible/allocation/supply/rate-limit/server/transport/success) | M |
| fresh authorization point | Local validation (target, calldata, quantity, signer, chain, value cap) of the untrusted response | M |
| fresh authorization point | On-chain simulation (`eth_estimateGas`) | M |
| fresh authorization point..T0 | Progress events (`RequestingMintTransaction`/`Validating`/`Simulating`) | O-NB |
| T0 | Near-T0 rewarm | M |
| T0 | `eth_sendRawTransaction` fan-out -- skipped under `--rehearsal` | M |
| after dispatch | Receipt polling (skipped under `--rehearsal`), `reporter.emit(Success)`, bounded flush, telemetry summary | M / O-NB / bounded wait / O |

Never obtained speculatively early and never obtained more than once per
attempt: the OpenSea wallet-specific authorization. It carries its own
short validity window, so `watch` neither fetches it ahead of the stage
opening (it could expire before use) nor hammers the endpoint -- exactly
one bounded-retry request at the point it is actually needed. See
"OpenSea authorization freshness" below.

## Freshness table

Every field that actually matters for a safe, correctly-priced,
authorized transaction is sourced fresh, immediately before it is used
to sign -- never from discovery-time or resolution-time metadata. `n/a`
where a field doesn't apply to that engine.

| Field | Discovery-time source | Final pre-sign source | Fail-closed check | Test |
|---|---|---|---|---|
| Stage start/end time | `NormalizedStage.window` (resolution) | `PublicStageProbe`/`OpenSeaStageProbe`'s fresh re-read every poll cycle, used directly by `wait_for_stage` | Stage `Ended` stops the wait with an error; a moved start is picked up live | `stage_start_moving_later_while_waiting_updates_the_target`, `..._moving_earlier_..._and_arms_promptly` |
| Nonce | n/a (never known ahead of time) | `eth_getTransactionCount`, re-read at every scheduler checkpoint (StateCheck/Refresh/Finalize) | A changed nonce between two prepares produces different signed output | `nonce_change_between_two_prepares_yields_different_signed_output` |
| Base fee / priority fee | n/a | `eth_getBlockByNumber`/`eth_maxPriorityFeePerGas`, re-read at every checkpoint | Changed fee data produces different signed output | `fee_refresh_changes_prepared_transaction` |
| Balance | n/a | `eth_getBalance`, read fresh in the prepare pipeline | Insufficient balance fails closed before signing | `insufficient_balance_fails_closed` |
| Wallet allocation remaining / minted count | `MintPlan`'s discovery-time read (display only) | `getMintStats` (PUBLIC) / the real OpenSea mint-builder response + local validation (OpenSea), read fresh at prepare time | Exceeding remaining allocation is rejected | `watch_wallet_allocation_exhausted_while_waiting_stops_safely` |
| Total / remaining supply | `MintPlan`'s discovery-time read (display only) | `getMintStats` fresh read | Quantity exceeding remaining supply fails closed | `validate_rejects_quantity_exceeding_collection_supply` |
| Mint value / price | discovery-time `stage.price` (OpenSea) is *never* trusted for value -- deliberately returns `None` (see `opensea_display_price_provenance_unavailable`) | PUBLIC: `getPublicDrop.mintPrice`, read fresh. OpenSea: the real, freshly-fetched mint-builder response's own `value` field | OpenSea: real value must equal `expected_price * quantity`, both freshly fetched moments apart, or `UnsafeValue` | `rejects_value_disagreeing_with_expected_stage_price` |
| Max gas cost / total spend caps | Operator-supplied, not discovered | Compared against the real, freshly-estimated gas cost immediately before signing | Exceeding either cap fails closed | `safety_caps_reject_gas_cost_over_cap` |
| Fee recipient | `getAllowedFeeRecipients` (PUBLIC only) | Same call, read fresh; OpenSea's fee recipient comes from the real mint-builder response, locally validated | An unauthorized/mismatched fee recipient is rejected | `opensea_response_with_wrong_minter_is_rejected_before_signing`-style validation tests |
| max_per_wallet / signed-mint bounds | OpenSea `stage.max_per_wallet` (display only) | `getSignedMintValidationParams`, read fresh; the real signed authorization's own params are bounds-checked against it | Exceeding the signer's bound is rejected | `validate_signed_mint_params_bounds` (internal) |
| OpenSea authorization itself | n/a (never exists ahead of activation) | The real `POST /drops/{slug}/mint` response, fetched exactly once per attempt, validated in the same attempt it is signed in | Any mismatch (target/chain/minter/quantity/value/signature/collection) is rejected before signing | the `opensea_response_with_*_is_rejected_before_signing` test family |

## Advisory background work

`watch`'s only background-shaped work is the periodic re-resolution
check (a plain `tokio::select!` race, not a spawned task -- see "Periodic
re-resolution" above) and, since this pass, the `ProgressReporter`
consumer task. Both are bounded, session-scoped, and cleanly cancel:
`tokio::select!` simply drops the losing branch's future when
`wait_for_stage` wins, and `ProgressReporter`'s consumer task ends on its
own once its sender is dropped (or is silently abandoned, past a bounded
500ms flush, if it is somehow still stuck). Neither ever holds a lock
across an `.await`, neither can panic into the mint-execution path (a
`ProgressReporter` consumer panic only ends that one task; a poisoned
telemetry lock is treated as "unavailable" via `try_lock`), and T0 never
awaits either one's completion.

## Local no-broadcast rehearsal

Both `kairox mint --rehearsal` and `kairox watch --rehearsal` run the
complete real pipeline (`mint`: benchmark, prewarm, every checkpoint,
fresh reads, real local signing/serialization; `watch`: additionally,
the early pool connect, full pre-T0 benchmark, stage polling, periodic
auto re-resolution, exact-stage exclusion after a clear ineligibility
rejection, and near-T0 rewarm) end to end for both the PUBLIC and
OpenSea engines, and stop immediately before `eth_sendRawTransaction` --
never sending a real or dummy transaction, never polling a receipt.

`watch --rehearsal` satisfies the same explicit-consent gate
`--auto-send` exists for on its own (a rehearsal never broadcasts, so it
needs no separate consent for *that*): `kairox watch <collection>
--wallet <w> --rehearsal` works standalone, or combine
`--auto-send --rehearsal` to be explicit about both. Output ends with
`REHEARSAL RESULT` / `REHEARSAL COMPLETE` (never `BROADCAST RESULT`),
including the local tx hash, selected engine/stage, and the same
`LatencyMetrics` timing breakdown a real run reports.

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

## Locality/connection-warming diagnostics

`kairox bench` reports, per configured RPC endpoint: label, role,
chain-id verification, bounded latency samples (median/p90/p95),
success/failure/timeout counts, and current read/send selection. A
submission-only (sequencer) endpoint is never read from to "benchmark"
it and never sent a dummy transaction -- its report says plainly that
submission latency was not measured because doing so would require a
real transaction. `kairox bench` also reports the official OpenSea REST
origin's latency using the same already-reused HTTP client `watch`/`mint`
use, classified by real HTTP status (200/404/401/403/429/5xx/timeout
/transport failure) rather than a single vague "no-record-or-error"
bucket, and labeled "first measured request"/"subsequent request" rather
than an unverifiable "cold"/"warm" claim.

Only the official REST API is ever used -- no private GraphQL endpoint,
no SIWE/browser-session impersonation, no `x-app-id` tricks, no spoofed
browser headers.

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
- The 30-second periodic re-resolution interval is fixed, not exposed as
  an operator-facing flag (a test-only environment variable exists purely
  so this behavior is testable in seconds rather than real minutes -- it
  is intentionally undocumented as a stable interface).
- There is no guarantee of winning a first-come-first-served mint merely
  by using `watch` -- physical network locality to the chain's RPC/
  sequencer infrastructure and to the OpenSea REST origin still matters,
  and `watch` cannot change where the operator's machine is deployed.
