# Robinhood Chain mainnet launch runbook

This is a copy/paste, in-order guide for running a real, competitive NFT
mint on **Robinhood Chain mainnet** (chain id **4663**) with Kairox. It
covers the three mint paths Kairox supports -- **PUBLIC**, **allowlist**,
and **FCFS/server-signed** -- separately, since each has a different T0
critical path. Read [docs/robinhood-testnet-validation.md](robinhood-testnet-validation.md)
and complete a controlled testnet acceptance run first if you have not
already.

**Placeholders vs. real values:** `0x...` is always a placeholder, never
something you can run directly. **Never paste a private key into any
chat.** `KAIROX_SIGNING_KEY` is read from your own terminal's environment
or an interactive prompt only.

## Official Robinhood Chain mainnet facts

| | |
|---|---|
| Chain ID | **4663** |
| Native gas token | ETH |
| Public RPC | `https://rpc.mainnet.chain.robinhood.com` |
| Sequencer | `https://sequencer.mainnet.chain.robinhood.com` |
| Sequencer feed | `wss://feed.mainnet.chain.robinhood.com` |
| Block explorer | `https://robinhoodchain.blockscout.com` |

**The public RPC is rate-limited and explicitly documented as not
recommended for production.** For a real competitive mint, configure at
least one additional provider (e.g. Alchemy) as a second `KAIROX_RPC_4663_*`
endpoint alongside (not instead of) the public one, so Kairox has more than
one independently-verified route to broadcast through. Never assume a
single free public endpoint is competitive infrastructure on its own.

## What the operator needs, per engine

| | PUBLIC | Allowlist | FCFS / server-signed |
|---|---|---|---|
| NFT collection address | required | required | required |
| SeaDrop contract | resolved automatically for Robinhood Chain (default SeaDrop 1.0 singleton) unless overridden | same | same |
| OpenSea slug | not used | required (`--slug`) | required (`--slug`) |
| OpenSea API key | not used | required (`KAIROX_OPENSEA_API_KEY`) | required |
| Public wallet address | required | required | required |
| Quantity | required | required | required |
| ETH balance | must cover worst-case mint value + gas | same | same |
| Spend/fee caps | `--max-mint-value-wei`/`--max-gas-cost-wei`/`--max-total-spend-wei` | same | same |

For a normal, verified Robinhood Chain drop, you do **not** need to find or
pass a SeaDrop contract address yourself -- Kairox already resolves it
(the same SeaDrop 1.0 singleton deployed identically across Ethereum, Base,
and Robinhood Chain mainnet). Only pass `--seadrop-contract` if you are
targeting a collection using a different, non-default SeaDrop deployment.

## 1. Configure RPC and secrets

```sh
export KAIROX_RPC_4663_0_URL=https://rpc.mainnet.chain.robinhood.com
export KAIROX_RPC_4663_0_ROLE=READ_ONLY   # the public endpoint: read-only role, never your only send route
export KAIROX_RPC_4663_0_LABEL=robinhood-mainnet-public

export KAIROX_RPC_4663_1_URL=https://YOUR-PROVIDER-URL   # <- your own paid provider (e.g. Alchemy)
export KAIROX_RPC_4663_1_ROLE=READ_WRITE
export KAIROX_RPC_4663_1_LABEL=robinhood-mainnet-provider

export KAIROX_SIGNING_KEY=0x...        # <- your real wallet's private key, set in your own terminal only
export KAIROX_OPENSEA_API_KEY=...      # <- only needed for allowlist/FCFS engines
```

## 2. `doctor` and `bench` (read-only)

```sh
./target/release/kairox doctor --json
./target/release/kairox bench --chain 4663
```

Confirm every configured endpoint shows `VERIFIED`/chain id 4663. If your
paid provider fails to connect, fix that before proceeding -- do not launch
on the free public endpoint alone.

## 3. `inspect` and `plan` (read-only)

```sh
./target/release/kairox inspect "$NFT" --chain 4663 --wallet "$WALLET"
./target/release/kairox plan "$NFT" --chain 4663 --wallet "$WALLET" --quantity "$QUANTITY"
```

Confirm the plan's stage window, fee recipient, mint value, and worst-case
spend all look correct before continuing.

## 4. Rehearsal (PUBLIC engine only, no transaction)

```sh
./target/release/kairox mint "$NFT" --chain 4663 --wallet "$WALLET" \
    --quantity "$QUANTITY" --rehearsal --yes
```

Runs the entire live pipeline against real mainnet state -- benchmarking,
connection warming, every scheduler checkpoint, a fresh nonce/fee/balance
read, and real local signing/serialization -- and stops immediately before
`eth_sendRawTransaction` would be called. Output ends with `REHEARSAL
COMPLETE`, never `BROADCAST RESULT`. Use this to validate timing and
connectivity against the real network before the actual launch, with zero
risk of a real transaction. (Allowlist/FCFS rehearsal is not implemented
yet -- see Known limitations below.)

## 5. PUBLIC mint

```sh
./target/release/kairox mint "$NFT" --chain 4663 --wallet "$WALLET" \
    --quantity "$QUANTITY" \
    --max-mint-value-wei "$MAX_MINT_VALUE_WEI" \
    --max-gas-cost-wei "$MAX_GAS_COST_WEI" \
    --max-total-spend-wei "$MAX_TOTAL_SPEND_WEI" \
    --send --yes
```

**What happens at T0:** by the time the stage-open instant arrives, Kairox
has already read and verified the stage, wallet allocation, and supply;
read a fresh pending nonce, base fee, priority fee, and balance; built,
signed, and RLP/hex/JSON-serialized the complete `eth_sendRawTransaction`
request body; and warmed a connection to every configured send endpoint.
At T0 it releases those exact, already-signed, already-serialized bytes to
every send-capable endpoint concurrently -- no state read, signing, or
serialization happens after the barrier. See
[docs/architecture.md](architecture.md#public-engine-hot-path-t0) for the
implementation this describes.

## 6. Allowlist mint (OpenSea-hosted)

**Important correction:** an allow-list stage's Merkle *root* may be
stored on-chain, but your wallet's specific Merkle *proof* is not
derivable from that root -- Kairox does not and cannot reconstruct it.
Today, Kairox has exactly one way to obtain a wallet-specific allow-list
proof: the official OpenSea Drops mint endpoint,
`POST /api/v2/drops/{slug}/mint`, which returns ready-to-validate
target/calldata/value (including the proof) for the requested minter and
quantity once an eligible stage is active. There is no separate
`--engine public` allow-list path -- `--engine public` only ever
constructs a `mintPublic(...)` transaction, never `mintAllowList(...)`
(enforced structurally: `protocol::seadrop` has no function that encodes
allow-list calldata locally, only one that decodes and validates it from
an OpenSea response).

```sh
./target/release/kairox mint "$NFT" --chain 4663 --wallet "$WALLET" \
    --engine opensea --slug "$SLUG" --quantity "$QUANTITY" \
    --max-mint-value-wei "$MAX_MINT_VALUE_WEI" \
    --send --yes
```

**What happens at T0:** everything static is prepared beforehand (OpenSea
client warmed, API key loaded, slug/wallet/quantity resolved, signer
ready, RPC clients warmed, spend caps fixed). At (or near) stage
activation, Kairox sends the mint request; OpenSea's response is decoded,
then every field is validated before any Ethereum signature: target,
chain, collection, minter, quantity, value, and the wallet's Merkle proof
against a *freshly re-read, authoritative on-chain root* (never the root
OpenSea itself might claim) -- see
`execution::opensea_validate::verify_allow_list_proof`. Only after that
passes does Kairox sign once, serialize once, and fan out. OpenSea's own
response latency (`opensea_mint_request_ms` in the printed metrics) is
real and external to Kairox; nothing about this path is "identical to
PUBLIC" the way an earlier draft of this document incorrectly claimed.

If a project's allow-list stage is ever independently verified to expose
a wallet's proof through some other, non-OpenSea source *before* T0,
Kairox could in principle validate and arm it early the same way PUBLIC
does -- but no such path exists in Kairox today, and one must not be
assumed or fabricated.

## 7. FCFS / server-signed mint (OpenSea-hosted)

```sh
./target/release/kairox mint "$NFT" --chain 4663 --wallet "$WALLET" \
    --engine opensea --slug "$SLUG" --quantity "$QUANTITY" \
    --max-mint-value-wei "$MAX_MINT_VALUE_WEI" \
    --send --yes
```

**What happens at T0:** everything static is already prepared beforehand
(OpenSea client constructed and connection warmed, API key loaded, slug
and wallet resolved, quantity validated, signer initialized, RPC clients
warmed and verified, spend caps fixed). If OpenSea only returns
wallet-specific mint data once the stage activates, Kairox sends its
already-built mint request the moment it can. The critical path from
there is real, external, and unavoidable: **OpenSea's own response
latency**, which Kairox does not control. Once the response arrives,
Kairox's own controlled work is small and fixed: decode once, validate
target/chain/collection/minter/quantity/value once, recompute the Merkle
proof or recover and verify the server's EIP-712 signature once, sign the
wallet transaction once, serialize once, then fan out. No validation step
is ever skipped for speed. See `opensea_mint_request_ms` and
`api_to_dispatch_ms` in the printed metrics to see exactly how much of the
total time was OpenSea's response latency versus Kairox's own.

## 8. Receipt verification

```sh
./target/release/kairox receipt --tx "$TX_HASH" --collection "$NFT" \
    --wallet "$WALLET" --quantity "$QUANTITY" --chain 4663
```

Never trust broadcast acceptance alone -- always confirm the real
`Transfer` event.

## If a broadcast is Uncertain

If a send times out or the connection drops with no response, Kairox
reports `UNCERTAIN` and never automatically retries, replaces, or
resubmits with a new signature -- doing so risks a double-send. Wait, then
use `kairox receipt` once you have a chance to check the real outcome. See
[docs/security.md](security.md).

## Controlled mainnet acceptance mint (do this BEFORE any high-demand launch)

Before relying on Kairox for a real competitive launch, perform exactly
one small, low-stakes acceptance mint on Robinhood Chain mainnet:

1. Chain 4663.
2. A legitimately controlled, disposable/low-value wallet -- not your main
   wallet, and never a shared/high-value one for this test.
3. A free or extremely low-cost real mainnet mint you are actually
   eligible for, if one is available; otherwise the smallest real value
   you're comfortable risking.
4. `--quantity 1`.
5. Strict fee/spend caps (`--max-mint-value-wei`/`--max-gas-cost-wei`/
   `--max-total-spend-wei`), set deliberately low.
6. `kairox inspect`, then `kairox plan`, then `kairox mint ... --rehearsal`
   (PUBLIC engine) first -- every one of these is read-only or
   non-broadcasting.
7. Only then, one real `kairox mint ... --send --yes`.
8. `kairox receipt` to independently confirm the mint.

Only after this single acceptance mint genuinely succeeds should Kairox be
considered ready for a high-demand launch. Do not skip straight to a
competitive launch on an unverified configuration.

## Known limitations

- `--rehearsal` is implemented for the single-wallet PUBLIC engine only.
  Allowlist and FCFS/server-signed rehearsal, and multi-wallet rehearsal,
  are not implemented yet -- rely on `plan`/`inspect` (read-only) plus the
  Robinhood Testnet runbook for those paths in the meantime.
- OpenSea's own response latency for allowlist/FCFS stages is external and
  cannot be reduced by Kairox -- see `opensea_mint_request_ms` in the
  printed metrics for the real, measured figure on each run.
- See [README.md](../README.md#known-limitations) for the rest of Kairox's
  standing limitations (no Ctrl-C handling, no batch receipt recheck,
  etc.), which apply identically on mainnet.
