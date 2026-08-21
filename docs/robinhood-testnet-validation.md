# Robinhood Chain Testnet validation runbook

This is a copy/paste, in-order guide for running a controlled acceptance
test of Kairox against **Robinhood Chain Testnet** (chain id **46630** --
not to be confused with Robinhood Chain mainnet, chain id 4663). It assumes
no prior programming experience. Every command below is meant to be copied
exactly as shown, except where a placeholder is called out explicitly.

**Placeholders vs. real values:** anywhere you see `0x...`, that is a
placeholder standing in for a real address you have not obtained yet.
**`0x...` is never something you can actually run.** Every step below tells
you exactly where the real value comes from before you use it.

**Never paste a private key into a chat with anyone, including an AI
assistant.** Every step below that needs a private key reads it from your
own terminal's environment variable or a secure interactive prompt, never
from anything you type into a chat window.

Network facts (official, do not substitute):

| | |
|---|---|
| Network | Robinhood Chain Testnet |
| Chain ID | **46630** |
| Native gas token | ETH |
| Public RPC | `https://rpc.testnet.chain.robinhood.com` |
| Sequencer | `https://sequencer.testnet.chain.robinhood.com` |
| Explorer | `https://explorer.testnet.chain.robinhood.com` |

The public RPC is rate-limited testing infrastructure, not
production-grade. If you hit rate limits, slow down between commands.

---

## 1. Build Kairox

```sh
cargo build --release
./target/release/kairox --version
```

You should see `kairox 0.6.0` (or later) printed. If this fails, stop here
-- nothing after this step will work.

## 2. Configure the Robinhood Testnet RPC

Kairox never has a built-in URL for any RPC endpoint -- you always tell it
where to connect, via environment variables:

```sh
export KAIROX_RPC_46630_0_URL=https://rpc.testnet.chain.robinhood.com
export KAIROX_RPC_46630_0_ROLE=READ_WRITE
export KAIROX_RPC_46630_0_LABEL=robinhood-testnet-public

export KAIROX_RPC_46630_1_URL=https://sequencer.testnet.chain.robinhood.com
export KAIROX_RPC_46630_1_ROLE=SEQUENCER
export KAIROX_RPC_46630_1_LABEL=robinhood-testnet-sequencer
```

These are real values from the official network facts above -- paste them
exactly as shown, nothing to fill in yourself in this step.

## 3. Run doctor

```sh
./target/release/kairox doctor --json
```

Look for an entry with `"chain_id":46630` and `"name":"Robinhood Chain
Testnet"` -- distinct from the `"chain_id":4663` entry (Robinhood Chain
mainnet). Confirm the testnet entry shows connected endpoints. If it
doesn't, re-check step 2 before continuing.

## 4. Run bench

```sh
./target/release/kairox bench --chain 46630
```

This is read-only -- it only measures RPC latency, it does not sign or
broadcast anything. Confirm both endpoints from step 2 show as connected
with the right chain id (46630). If either shows `WRONG_CHAIN`, stop --
that endpoint is misconfigured or pointed at the wrong network.

## 5. Configure a disposable test wallet

Do not use a wallet that holds anything of real value anywhere, ever, for
this. Generate a fresh one with any wallet tool you already trust (Kairox
does not generate wallets for you -- this is intentional).

Once you have a fresh test wallet's private key, set it as an environment
variable in your own terminal (never in a file you might commit, never in
a chat message):

```sh
export KAIROX_SIGNING_KEY=0x...   # <- your disposable test wallet's private key
```

If you would rather not put it in an environment variable, Kairox will
prompt you for it interactively instead whenever a live `--send` actually
needs to sign -- just leave `KAIROX_SIGNING_KEY` unset.

Also note your test wallet's **public address** (never the private key) --
you'll need it below:

```sh
export WALLET=0x...   # <- your disposable test wallet's PUBLIC address only
```

## 6. Get testnet ETH from the official faucet

Robinhood Chain Testnet's official faucet is the only legitimate source of
testnet ETH for this wallet. Follow Robinhood's own published faucet
instructions for chain id 46630, sending funds to the `$WALLET` address
from step 5. Do not use any third-party "faucet" someone offers you in
chat or a forum.

Confirm funds arrived by checking `$WALLET` on the official explorer:
`https://explorer.testnet.chain.robinhood.com`.

## 7. Deploy the controlled test contracts

The prepared (but not yet run, by design) deployment lab lives at
[`testnet-lab/robinhood-testnet/`](../testnet-lab/robinhood-testnet/).
Follow that directory's own `README.md` first -- it explains the
Foundry setup and the mandatory chain-id guard every script in it enforces
(it will refuse to run against anything other than chain 46630, with no
fallback to mainnet).

```sh
cd testnet-lab/robinhood-testnet
./scripts/guard_chain_id.sh "$KAIROX_RPC_46630_0_URL"   # aborts if not 46630
forge script script/DeployLab.s.sol \
    --rpc-url "$KAIROX_RPC_46630_0_URL" \
    --broadcast -vvvv
```

This is the one step in this runbook that actually spends your testnet
ETH and creates real transactions -- read the lab's own README fully
before running it.

## 8. Capture the REAL deployed NFT and SeaDrop addresses

The deploy script above prints the two addresses it deployed. Copy them
from your terminal's actual output -- never guess, never reuse an address
from an example, never reuse a mainnet address.

## 9. Export the real addresses

```sh
export NFT='0x...'        # <- the REAL deployed test collection address from step 8
export SEADROP='0x...'    # <- the REAL deployed SeaDrop address from step 8
```

(`$WALLET` was already exported in step 5.)

At this point, `NFT`, `SEADROP`, and `WALLET` all hold real, verified
values -- this is the last step where `0x...` appears as a placeholder in
this document.

## 10. `kairox inspect`

```sh
./target/release/kairox inspect "$NFT" \
    --chain 46630 --seadrop-contract "$SEADROP" --wallet "$WALLET"
```

Read-only. Confirms Kairox can see the real on-chain public-stage config
and supply you just deployed.

## 11. `kairox plan`

```sh
./target/release/kairox plan "$NFT" \
    --chain 46630 --seadrop-contract "$SEADROP" --wallet "$WALLET" \
    --quantity 1
```

Read-only. Builds the full mint plan (fee recipient, value, gas, calldata)
without signing or sending anything.

## 12. Dry-run mint (WITHOUT `--send`)

```sh
./target/release/kairox mint "$NFT" \
    --chain 46630 --seadrop-contract "$SEADROP" --wallet "$WALLET" \
    --quantity 1
```

Still nothing is signed or broadcast -- `--send` is required for that, and
Kairox refuses to broadcast without it. Confirm the output looks
sane before moving on.

## 13. Live testnet quantity=1 mint

Only after steps 10-12 all look correct:

```sh
./target/release/kairox mint "$NFT" \
    --chain 46630 --seadrop-contract "$SEADROP" --wallet "$WALLET" \
    --quantity 1 --send
```

You will be shown a confirmation summary and asked to confirm before
anything is actually signed or sent. This is the first real transaction
in this runbook that spends `$WALLET`'s testnet ETH.

## 14. Receipt verification

```sh
./target/release/kairox receipt \
    --tx <TX_HASH_FROM_STEP_13> \
    --collection "$NFT" --wallet "$WALLET" --quantity 1 \
    --chain 46630
```

Confirms the mint independently from the actual on-chain `Transfer`
event, not just "the broadcast was accepted."

## 15. Timed T=0 test

Reschedule the public stage's start time a few minutes into the future
(see the lab's `script/ResetLab.s.sol`, `PUBLIC_STAGE_START` env var), then
run a `plan` a few minutes before that time and observe Kairox's scheduled
pre-signing/dispatch behavior leading up to it. Use a second disposable
test wallet for this so step 13's mint doesn't interfere.

## 16. Public failure cases

Try quantity 0, a quantity exceeding the wallet limit, and (after the
stage's `endTime`) a mint after the stage has closed. Confirm Kairox
reports each as a clear, typed failure and never broadcasts anything.

## 17. Allow-list test

Follow the lab README's allow-list section to configure the single-leaf
allow-list stage for one test wallet, then run `kairox mint --engine
public` (SeaDrop's on-chain `mintAllowList` path) for that wallet with
`--quantity 1`. This exercises Kairox's real Merkle-proof verification
against genuine on-chain state, not a mock.

## 18. Multi-wallet test (only after every single-wallet step above passes)

Fund a second and third disposable test wallet the same way as step 5-6,
write a small manifest file listing all three, and run:

```sh
./target/release/kairox mint "$NFT" \
    --chain 46630 --seadrop-contract "$SEADROP" \
    --wallet-manifest ./manifest.json \
    --engine public --send --yes
```

Only attempt this after every earlier step has genuinely passed --
multi-wallet is strictly more complex and should never be the first thing
you validate.

---

## If anything goes wrong

- **Uncertain broadcast** (no response after `--send`): do not panic, do
  not re-run the mint command. Wait, then use `kairox receipt` once you
  have a chance to check the real on-chain outcome -- see
  [`docs/security.md`](security.md).
- **Any command reports a chain id other than 46630** anywhere in this
  runbook: stop immediately and re-check step 2. Never proceed assuming
  it's "close enough."
