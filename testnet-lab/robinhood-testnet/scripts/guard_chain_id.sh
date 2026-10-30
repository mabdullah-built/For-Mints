#!/usr/bin/env bash
# Pre-flight guard for the Robinhood Chain Testnet lab: aborts BEFORE
# invoking forge at all if the RPC endpoint's actual reported chain id is
# not 46630. This is defense in depth on top of (not a replacement for)
# the `require(block.chainid == 46630, ...)` guard inside every Solidity
# script in this lab -- two independent checks, never one.
#
# Usage: scripts/guard_chain_id.sh <rpc_url>
# Exits non-zero and prints nothing sensitive if the chain id does not
# match. Never falls back to 4663 (Robinhood Chain mainnet) or any other
# chain -- an unreachable RPC or any chain id other than exactly 46630 is
# treated as ABORT.

set -euo pipefail

ROBINHOOD_TESTNET_CHAIN_ID=46630

if [ $# -ne 1 ]; then
    echo "usage: $0 <rpc_url>" >&2
    exit 2
fi

RPC_URL="$1"

if ! command -v cast >/dev/null 2>&1; then
    echo "ABORT: 'cast' (Foundry) is not installed; cannot verify chain id before proceeding." >&2
    exit 1
fi

REPORTED_CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || true)"

if [ -z "$REPORTED_CHAIN_ID" ]; then
    echo "ABORT: could not read a chain id from the given RPC endpoint. Refusing to proceed." >&2
    exit 1
fi

if [ "$REPORTED_CHAIN_ID" != "$ROBINHOOD_TESTNET_CHAIN_ID" ]; then
    echo "ABORT: RPC endpoint reports chain id $REPORTED_CHAIN_ID, expected exactly $ROBINHOOD_TESTNET_CHAIN_ID (Robinhood Chain Testnet). Refusing to proceed -- this NEVER falls back to 4663 (mainnet) or any other chain." >&2
    exit 1
fi

echo "Chain id verified: $REPORTED_CHAIN_ID (Robinhood Chain Testnet). Safe to proceed."
