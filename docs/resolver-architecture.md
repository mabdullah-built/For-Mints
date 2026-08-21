# Mint protocol resolver

## Reference study (Part 1)

Re-studied `.research/nft-public-mint` (TypeScript SeaDrop bot) and
`.research/osnm-z` (Rust multi-mint bot) specifically for this pass, on top
of the comparison already done for the mainnet-hardening pass earlier in
this project. Both were already the basis for Kairox's existing T0
architecture (prebuilt/pre-signed transaction bytes, same-raw-tx fanout,
connection warming, T-minus scheduling, receipt-truth-over-simulation) — see
`docs/architecture.md`'s "Public engine hot path" section. Nothing new and
legitimate was found in this second pass beyond what Kairox already does;
neither reference implements a multi-protocol resolver of the shape
requested here — `osnm-z` hardcodes a fixed set of supported contracts,
`nft-public-mint` targets exactly one SeaDrop collection per config file.
This section's engineering technique (protocol fingerprinting → adapter
registry → confidence-gated resolution) is therefore original to this pass,
not adapted from either reference.

Comparison against the current Kairox architecture, item by item:

| Area | Reference repos | Kairox (this pass) |
|---|---|---|
| Mint-path resolution | Fixed per-config, no runtime detection | New: `AdapterRegistry` (below) |
| Stage discovery | Direct `getPublicDrop()`/API call, assumed correct | Unchanged: `execution::plan`/`execution::watch` |
| Pre-sign/pre-serialize | Yes, both | Unchanged: `PreparedTransaction`/`PreparedBroadcast` |
| Public mint | Direct calldata construction | Unchanged: `protocol::seadrop::encode_mint_public` |
| Allowlist | `osnm-z`: local Merkle proof from a config file (proof supplied by operator, not derived) | Unchanged: OpenSea API only, revalidated locally |
| Server-signed | Not implemented in either reference | Unchanged: `opensea_validate` EIP-712 recovery |
| Multiwallet | `osnm-z`: concurrent, own nonce per wallet | Unchanged: `execution::multi_wallet` |
| Timing | Both: absolute target + local countdown | Unchanged, extended this pass by `execution::watch`'s long-horizon poll |
| Connection warming | Both: persistent HTTP clients, pre-opened | Unchanged: `RpcPool::rewarm_all` |
| RPC fanout | Both: same raw bytes to N endpoints | Unchanged: `broadcast_to_all` |
| Receipt verification | `osnm-z`: polls receipt only, no log decode | Unchanged, stronger: `protocol::logs` decodes and attributes Transfer events |
| Error handling | Ad hoc per-repo | Unchanged, extended this pass: `KairoxErrorCode::{UnsupportedProtocol,AmbiguousProtocol}` |
| Unsupported protocol | Neither reference has this concept -- both assume the configured contract is correct | New this pass (below) |

## The resolver (current)

```
collection/wallet/quantity/[slug]
        |
        v
AdapterRegistry::resolve()
  tier 0: OpenSeaDropsAdapter -- operator --slug (always wins outright), OR
                                 auto-discovered active/upcoming NON-PUBLIC
                                 OpenSea stage (signed-presale/allowlist/
                                 FCFS/FCFA); never matches a plain public
                                 stage -- see below
  tier 1: SeaDropAdapter      -- on-chain getPublicDrop(), Active/NotStarted
  tier 2: GenericVerifiedContractAdapter -- trusted-registry bytecode match,
                                 OR verified-source semantic resolution
                                 (HIGH); operator --generic-schema + ERC-165
                                 alone (LOW, never live-sends)
        |
        v
  exactly one High-confidence Detection, or:
    UNSUPPORTED_PROTOCOL  (no tier matched)
    AMBIGUOUS_PROTOCOL    (>1 match within the same tier)
```

`execution::resolver::AdapterRegistry` tries adapters tier by tier
(ascending `priority()`); the first tier that produces any match decides
the outcome. A tier with more than one `High`-confidence match is
`AmbiguousProtocol` (a genuine tie, never guessed between). A `Low`-
confidence match is recorded but never resolves anything on its own — see
`ProtocolEvidence`/`Confidence` in `src/execution/resolver.rs`. Both `mint
--engine auto` and `watch --engine auto` call the same
`cli::commands::mint::resolve_auto_engine` and print the winning evidence
(`resolved_engine`, `adapter`, `confidence`, `source`) before proceeding.

**`OpenSeaDropsAdapter` is tier 0, ahead of native `SeaDropAdapter`.** This
was a deliberate priority *swap* from an earlier pass, made to fix a real
observed bug: an active, eligible OpenSea-hosted signed-presale stage
existing alongside a later on-chain public stage, where an explicit
`--engine public` invocation waited for the wrong (later, public) one
instead. `OpenSeaDropsAdapter` only ever matches a currently-active (or,
for `watch`, upcoming — `allow_not_yet_started`) *non-public* stage; a
plain public stage (or no OpenSea drop at all) makes it return no match,
which — since a tier with zero matches is simply skipped, never
`AmbiguousProtocol` — falls straight through to `SeaDropAdapter` at tier 1.
Slug auto-discovery (`opensea::discovery::resolve_drop`) is best-effort:
any OpenSea transport/auth/server error is treated identically to "no
drop discovered," never propagated, so OpenSea's availability can never
block a collection whose native on-chain public stage still works.
`GenericVerifiedContractAdapter` (tier 2, unchanged from its own pass) is
tried last, and only reaches `High` confidence via an exact trusted
bytecode-hash match or unambiguous verified-source semantic resolution —
see `docs/generic-engine.md`.

## What this codebase does NOT yet add, and why

A `GenericExternalTransactionEngine` that signs externally-produced
calldata from a third-party transaction builder, new dedicated launchpad
adapters, and token-gated SeaDrop support are **not implemented**. Each is
a genuinely separate, safety-critical body of work — trusting a third
party's `to`/`data`/`value` tuple, or arming a live-send path against a
contract Kairox has never independently verified mint semantics for, is
exactly the kind of decision that demands its own dedicated pass with a
real verified-ABI/bytecode fingerprinting model and a real validator, not
a rushed addition bolted onto an unrelated change. See the current
session's final report for what was and wasn't attempted.

## Adding a future adapter

1. Implement `execution::resolver::MintAdapter` for the new protocol:
   `name()`, `priority()` (its position in the hierarchy), and
   `detect()` returning `Some(Detection)` only on real, checkable evidence
   (never "the address doesn't look like anything else").
2. Implement the actual prepare/sign/broadcast/receipt-truth logic as its
   own function or module (mirroring `execution::live`/`execution::opensea_engine`
   — not squeezed into the adapter trait, which is detection-only in this
   design).
3. Register it in `cli::commands::mint::resolve_auto_engine`'s
   `AdapterRegistry::new(vec![...])` call, and add a variant to
   `execution::resolver::ResolvedEngine` plus the corresponding
   `SelectedEngine`/`ResolvedWatchEngine` match arms in `mint.rs`/`watch.rs`.
4. Add adapter-specific tests: a positive detection test, a negative (no
   match) test, and an ambiguity test if it can plausibly overlap another
   adapter's tier.
