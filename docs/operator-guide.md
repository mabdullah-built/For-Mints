# Operator guide

A realistic walkthrough of setting up and running Kairox, end to end.

## 1. Install and write a starter config

```sh
cargo build --release
./target/release/kairox init
# Wrote starter config to /home/you/.config/kairox/config.toml
```

Open it and point the `read_rpc_env`/`send_rpc_env`/`api_key_env` fields at whichever environment variable names you actually intend to export — the file itself never holds a secret value, only names:

```toml
version = 1

[defaults]
chain = "ethereum"
engine = "auto"

[chains.ethereum]
read_rpc_env = ["KAIROX_RPC_1_0_URL"]
send_rpc_env = ["KAIROX_RPC_1_0_URL"]

[opensea]
api_key_env = "KAIROX_OPENSEA_API_KEY"
```

## 2. Export the real values

```sh
export KAIROX_RPC_1_0_URL="https://your-real-rpc-endpoint.example/v1"
export KAIROX_OPENSEA_API_KEY="your-real-opensea-key"     # only if using --engine opensea
export KAIROX_SIGNING_KEY="0xyourprivatekey"               # only needed for --send, and only
                                                             # at the moment you actually broadcast
```

`KAIROX_SIGNING_KEY` can be left unset — Kairox will prompt for it interactively when a `--send` session actually needs to sign.

## 3. Check the environment

```sh
kairox doctor
```

Confirms: Kairox version, dry-run-by-default banner, whether a signing key / OpenSea key is configured (never their values), your config file's parse status, and whether each configured chain's RPC endpoint(s) actually connect and report the expected chain id. Fix anything reported `WARN`/`FAIL` before continuing. `kairox doctor --json` gives the same information as one JSON object, for scripting.

## 4. Inspect the collection

```sh
kairox inspect 0xYourCollectionAddress --wallet 0xYourWallet
```

Shows the collection's current on-chain public-stage config (price, window, per-wallet cap, fee), supply, and your wallet's current allocation. Add `--slug some-collection-slug` to also see OpenSea's off-chain drop metadata (clearly separated, never treated as on-chain-verified).

## 5. Build a plan

```sh
kairox plan 0xYourCollectionAddress --wallet 0xYourWallet --quantity 1
```

The authoritative dry-run plan: fee recipient, mint value, worst-case gas/spend, calldata, and the stage window/status. Nothing is signed or sent. Add `--json --output plan.json` to also get a machine-readable `ExecutionPlanReport` with a stable `plan_id`.

Adjust the safety caps if the defaults don't match what you're comfortable risking:

```sh
kairox plan ... --max-mint-value-wei 50000000000000000 \
                 --max-gas-cost-wei 20000000000000000 \
                 --max-total-spend-wei 70000000000000000
```

## 6. Dry-run the actual mint command

```sh
kairox mint 0xYourCollectionAddress --wallet 0xYourWallet --quantity 1
```

Identical to `plan` in substance — this is the same command you'll add `--send` to, so dry-running it first confirms the engine selection (`--engine auto`/`public`/`opensea`) and every flag are what you expect before you ever risk a live broadcast.

## 7. Go live

```sh
kairox mint 0xYourCollectionAddress --wallet 0xYourWallet --quantity 1 --send
```

You'll see a `LIVE SEND CONFIRMATION` summary (chain, wallet, collection, quantity, mint value, worst-case spend, target contract, planned stage-open time, send-capable endpoint count) on stderr, then a prompt: type `yes` to proceed, anything else to abort with nothing broadcast. Pass `--yes` to skip the interactive prompt in a scripted/unattended run — it only bypasses the *prompt*, never any of the protocol/safety checks that ran to build the plan.

Once confirmed, Kairox loads the signing key, verifies it resolves to `--wallet`, waits for the scheduled checkpoints, signs, and broadcasts the identical raw transaction to every send-capable endpoint. The final `BROADCAST RESULT` block shows the tx hash, each endpoint's outcome, and the receipt verification result.

Add `--json --output session.json` to get a `SessionReport` (with `session_id`/`plan_id`) instead of the human summary — progress/confirmation text still goes to stderr either way, so stdout stays exactly one JSON object.

## 8. Multi-wallet sessions

```sh
kairox mint 0xYourCollectionAddress --wallet-manifest ./wallets.json --engine public --send
```

Requires an explicit `--engine public` or `--engine opensea` (`auto` isn't supported for a manifest — there's no single right answer across multiple wallets). Each manifest entry names its own signing-key environment variable; every wallet's key is verified against its declared address before use. An aggregate preflight (spend cap, and for OpenSea sessions, stage supply) runs once for the whole eligible set before any wallet is signed.

## 9. If something needs a recheck

```sh
kairox receipt --tx 0xYourTxHash --collection 0xYourCollectionAddress --wallet 0xYourWallet --quantity 1
```

Read-only, uses only a verified read RPC endpoint, never resubmits anything. Use it whenever you have a tx hash and want an independent, evidence-based answer to "did this actually mint."

### Uncertain

A wallet reported **Uncertain** means no endpoint gave a definite accept or reject before timing out — the true outcome is genuinely unknown. Do not resend, do not treat it as failed. Wait, then recheck with `kairox receipt` once you have (or the network has propagated) a tx hash.

### Receipt mismatch (`CONFIRMED_EXECUTION_MISMATCH`)

The transaction executed successfully on-chain, but the expected mint evidence (the right quantity of unique-token-id `Transfer` events to your wallet) wasn't found. This is terminal — the transaction definitely ran; only the result differed from what was expected. Investigate before doing anything else with that wallet/nonce.

### Eligibility failure / supply exhausted

Both are terminal, protocol-level answers reported before any signing happens (`NOT_ELIGIBLE`/`ALLOCATION_EXCEEDED`/`SUPPLY_EXHAUSTED`) — nothing to retry until the underlying condition (stage timing, your wallet's allocation, remaining supply) actually changes.
