# Robinhood Chain Testnet validation lab (prepared, NOT executed)

This directory is a **prepared, uncompiled, unexecuted** Foundry project for
deploying a tiny, disposable SeaDrop-compatible test collection on
**Robinhood Chain Testnet (chain id 46630)** only, so Kairox's real
EVM/RPC/signing/broadcast/receipt behavior can be validated end to end
against a genuine testnet.

**Status: prepared for operator review, not built, not deployed, not run.**
No `forge` toolchain was available in the environment this was authored in,
so nothing here has been compiled or dry-run. Read every script before
running it. See [`docs/robinhood-testnet-validation.md`](../../docs/robinhood-testnet-validation.md)
for the full step-by-step operator runbook this lab is one part of.

## What this is

- A minimal ERC721 test collection wired to the real, upstream
  [`ProjectOpenSea/seadrop`](https://github.com/ProjectOpenSea/seadrop)
  contracts (installed as a Foundry dependency, not reimplemented from
  scratch) — the same protocol Kairox's `src/protocol/seadrop.rs` and
  `src/protocol/seadrop_crypto.rs` were independently cross-checked
  against. Using the real upstream contracts, rather than a hand-rolled
  clone, is deliberate: it is the only way to be confident the lab's
  on-chain ABI genuinely matches what Kairox decodes.
- Deploy/configure/reset scripts, each with a hard `block.chainid == 46630`
  guard as the *first* line of execution -- if the connected RPC endpoint
  reports any other chain id (including Robinhood Chain **mainnet**, 4663),
  the script reverts immediately. There is no fallback chain id.
- A max supply of ~20, a public free-mint stage with a small per-wallet
  limit (2-3), a start time that can be scheduled in the future (for a
  timed T=0 test), and a single-leaf allow-list stage for one test wallet.

## What this is NOT

- Not a production deployment mechanism.
- Not wired to OpenSea's API in any way -- OpenSea has no official testnet
  support for Robinhood Chain Testnet, and Kairox does not fabricate any.
  This lab only exercises Kairox's **direct on-chain public/allow-list**
  SeaDrop paths (`--engine public`), which is sufficient to validate real
  RPC/signing/broadcast/receipt behavior. The existing `tests/e2e_localhost.rs`
  harness remains the authoritative test for OpenSea wallet-specific REST
  (server-signed mint, allowlist-via-API) behavior.
- Not a source of a real private key. `PRIVATE_KEY` is read from an
  environment variable at script-run time only; it is never written to any
  file in this directory, never hardcoded, and never printed.

## Layout

```
foundry.toml                  Standard Foundry config; remaps to a `lib/seadrop`
                               dependency (`forge install ProjectOpenSea/seadrop`)
                               that must be installed before building.
src/RobinhoodTestnetCollection.sol
                               A thin ERC721SeaDrop subclass with no
                               behavior beyond upstream SeaDrop -- exists
                               only to give the test collection its own
                               name/symbol/max-supply at construction.
script/DeployLab.s.sol        Deploys SeaDrop (if needed) + the test
                               collection, configures the public and
                               allow-list stages. Guarded to chain 46630.
script/ResetLab.s.sol         Reconfigures stages on an already-deployed
                               test collection (e.g. to reschedule a timed
                               stage) without redeploying. Guarded to
                               chain 46630.
scripts/guard_chain_id.sh     Standalone pre-flight guard: aborts before
                               invoking `forge` at all if `cast chain-id`
                               against the given RPC URL is not 46630.
```

## Before running anything (operator checklist)

1. Install Foundry (`curl -L https://foundry.paradigm.xyz | bash && foundryup`)
   if not already installed.
2. `cd testnet-lab/robinhood-testnet && forge install ProjectOpenSea/seadrop`
   to pull the real upstream contracts as a dependency.
3. `forge build` and read the compiler output. Nothing in this lab has been
   compiled by the author of these files.
4. Read every script in `script/` and `scripts/` yourself before running it.
5. Follow [`docs/robinhood-testnet-validation.md`](../../docs/robinhood-testnet-validation.md)
   from the top -- it sequences this lab correctly relative to funding a
   disposable test wallet and running Kairox itself.
