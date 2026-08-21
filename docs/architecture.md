# Architecture

## Module layout

```
src/
  config/       TOML config parsing/validation, precedence resolution, config-driven RPC endpoint lookup
  cli/          argument parsing (args.rs), command dispatch (mod.rs), per-command logic (commands/),
                chain/RPC resolution shared by commands (context.rs), report types (report.rs)
  domain/       pure math: EIP-1559 fees, spend safety caps, wallet/collection supply arithmetic, timing
  chain/        RPC transport, endpoint config/pool/benchmarking, the chain registry
  protocol/     SeaDrop calldata encode/decode, EIP-712/Merkle crypto, Transfer-log mint verification
  opensea/      OpenSea Drops API client, request/response models, typed errors
  signing/      local signer, raw-key loading, EIP-1559 transaction encoding
  execution/    everything that turns validated inputs into a plan, then (optionally) a signed,
                broadcast, receipt-verified transaction -- public engine, OpenSea engine,
                multi-wallet orchestration, broadcast fan-out, receipt polling, errors/metrics
```

## Config

`config::resolve_runtime_config` is the one place chain/engine precedence is decided (CLI > `KAIROX_CHAIN`/`KAIROX_ENGINE` > config `[defaults]` > compiled default). `cli::context::resolve_chain_and_runtime` is the one place every command calls it from; `cli::context::config_endpoints_for_chain` is the one place a config's `[chains.*]` entry gets turned into actual `RpcEndpoint`s (falling back to `KAIROX_RPC_<chainId>_*` when config names nothing usable). No command re-implements either lookup.

## CLI

`cli::args` defines the clap surface; `cli::mod::run_with` dispatches to `cli::commands::*`, threading the resolved `--config` path down into every command. `cli::context` holds chain/RPC resolution; `cli::report` holds every `--json`/`--output` report type (`ExecutionPlanReport`, `SessionReport`, `WalletReport`, `BroadcastOutcomeReport`) plus `plan_id`/`session_id` generation and the atomic-ish report-file writer.

## Domain

Pure, I/O-free math: `Eip1559Fees` (enforces `max_fee >= base_fee`, `priority <= max_fee`), `SafetyCaps` (mint value / gas cost / total spend ceilings, checked before signing), `WalletAllocation`/`CollectionSupply` (remaining-allocation arithmetic, fails closed on any inconsistent on-chain state), `timing` (stage-window/scheduler math).

## Chain / RPC

`chain::rpc::RpcClient` wraps a pluggable `Transport` (real `HttpTransport`, or `MockTransport` in tests) with chain-id verification baked in at connect time. `chain::endpoint::EndpointRole` (`ReadWrite`/`ReadOnly`/`SendOnly`/`Sequencer`/`Private`/`Public`) gates what an endpoint may be used for. `chain::pool::RpcPool` holds every connected endpoint for a chain, benchmarks read latency, and deterministically selects the preferred read endpoint and the send-endpoint set. `chain::config::load_chain_endpoints` reads the `KAIROX_RPC_<chainId>_<n>_*` environment convention; `config::resolve_chain_rpc_endpoints` reads a config file's named variables instead — both produce the same `RpcEndpoint` type.

## SeaDrop protocol

`protocol::seadrop` locally *encodes* only `mintPublic(...)` calldata -- the one mint Kairox can construct from on-chain state alone. Allow-list and server-signed calldata are only ever *decoded* (from an untrusted OpenSea API response) and locally re-validated (Merkle proof recomputed against a freshly re-read on-chain root; EIP-712 signature recovered and its signer's authorization checked on-chain) before Kairox ever signs -- Kairox has no wallet-specific Merkle proof to construct an allow-list mint from independently, and never assumes one is derivable merely because a root is on-chain. Token-gated mints are recognized but explicitly rejected as unsupported. `protocol::seadrop` also selects a fee recipient per the contract's restriction rules. `protocol::seadrop_crypto` reproduces the EIP-712 domain/digest for server-signed mints and the Merkle leaf/proof verification for allow-list mints, cross-checked against the real `ProjectOpenSea/seadrop` contract source rather than assumed. `protocol::logs` decodes ERC-721/ERC-1155 `Transfer` events and attributes them to a specific minter — the only source of truth Kairox trusts for "did this wallet actually receive a token."

## OpenSea

`opensea::client` calls the official Drops API (`get_drop_details`, `request_mint_transaction`) with a bounded-retry policy that distinguishes retryable failures (timeout, 5xx, 429) from terminal ones (4xx eligibility/auth/not-found). Every response is untrusted input: `execution::opensea_validate` locally re-derives and checks everything the API claimed — target contract, collection, quantity, wallet, value, Merkle proof or EIP-712 signature — against on-chain state, before any of it is ever signed.

## Public engine hot path (T=0)

`execution::prepared::prepare_live_transaction` does every expensive step (nonce/fee/balance/supply reads, gas simulation, signing, RLP serialization, hex-encoding the `eth_sendRawTransaction` body) *before* the scheduled mint-open time. `execution::scheduler` sleeps to precise checkpoints (state-check, refresh, finalize) using a coarse-then-fine sleep strategy so the final approach to T=0 is not spent in a single long, imprecise sleep. At T=0, `execution::broadcast::broadcast_to_all` sends the exact same prebuilt bytes to every send-capable endpoint concurrently — no hex-encoding, JSON construction, or serialization happens on this path; it was all done ahead of time.

## OpenSea engine's unsigned barrier

`execution::opensea_engine::prepare_opensea_wallet_unsigned` and `finalize_and_broadcast_opensea_wallet` are two separate steps specifically so a multi-wallet OpenSea session can gather every wallet's own unsigned response first, run `execution::multi_wallet::check_opensea_aggregate_invariants` once over the whole eligible set (session spend cap, then the minimum stage-supply ceiling across every stage-constrained wallet, checked against a freshly-read `currentTotalSupply`), and only then release every eligible wallet's finalize+broadcast together. A single-wallet OpenSea session has no aggregate to check, so it uses the combined `run_opensea_mint_for_wallet` convenience function instead — there is no "streaming" mode anymore; every multi-wallet OpenSea session takes the barrier path unconditionally (a no-op, zero-added-latency, when nothing needs checking).

## Multi-wallet orchestration

`execution::multi_wallet` runs up to `manifest::MAX_WALLETS` (50) wallets concurrently via `futures_util::stream::buffered`, never `tokio::spawn`/`JoinSet` — every wallet task only borrows shared session state (the RPC pool, the OpenSea client), so concurrency stays structured and resolves/cancels naturally with the calling function, with no detached background task that could outlive a session. `execution::broadcast::BroadcastLimiter` bounds the real number of concurrent `eth_sendRawTransaction` requests in flight across the whole session (not just per-wallet), since wallets reach their own dispatch at different times. Results are reassembled in manifest order regardless of completion order.

## Receipt verification

`execution::receipt::poll_receipt` bounded-polls for a receipt, then requires the decoded `Transfer` log evidence to exactly match the expected quantity with unique token ids before reporting success — see [docs/security.md](security.md#receipt-truth).

## Session/plan/error-code reporting

`cli::report::compute_plan_id` hashes (truncated keccak256) the safe facts that define a planned mint intent — chain id, collection, engine, wallet(s), quantity, stage window, a config-path fingerprint — deliberately excluding the generation timestamp, so two `plan`/`mint` invocations for the same underlying intent produce the same `plan_id`; `generated_at` carries per-invocation timing separately. `cli::report::generate_session_id` produces a fresh random 128-bit id before any signing happens, used only for correlating a session's own report/logs with itself. `execution::errors::KairoxErrorCode` maps every structurally-typed internal error onto a stable external code; `BroadcastOutcome::error_code`/`ReceiptState::error_code` cover the two outcome families (`BROADCAST_FATAL`/`BROADCAST_UNCERTAIN`, `RECEIPT_REVERT`/`RECEIPT_MINT_MISMATCH`) that are not `KairoxError`s at all, since they're not failures of the Kairox process — they're accurately-classified real-world outcomes. Every error surfaced by the CLI is printed on stderr as `error[CODE]: message` (`cli::run_with`'s top-level error handler), so scripts can match on the stable code without parsing the human message text; a config-file error specifically (either the RPC-env-only path or the newer TOML config-file path) always carries `CONFIG_INVALID`, proven end-to-end in `tests/e2e_localhost.rs`'s `bad_config_*` tests.

## Timeouts and retry policy

| Timeout | Default source | Where |
|---|---|---|
| Per-RPC-call timeout | `RpcEndpoint`'s configured timeout (`KAIROX_RPC_*_TIMEOUT_MS`, or `chain::endpoint::DEFAULT_RPC_TIMEOUT`) | `chain::rpc::HttpTransport` |
| Broadcast/receipt timeout | `execution::profile::ExecutionProfile::for_chain` (per-chain default), overridable via `--receipt-timeout-secs`/`--receipt-poll-interval-ms` | `execution::live`, `execution::opensea_engine` |
| OpenSea API call timeout | Fixed 10s (`load_opensea_client`) | `cli::commands::mint` |
| `kairox receipt` recheck timeout | `--timeout-secs` (default 10s) — deliberately short: a bounded recheck, not an open-ended watch | `cli::commands::receipt` |

Retry policy is bounded and explicit everywhere it exists, never silent/unbounded: `execution::opensea_engine`'s mint-request retry loop is capped at a fixed `MAX_ATTEMPTS` (3) and only retries `Retryable`-categorized errors (timeout, 5xx, 429) — never a `Fatal` or `MustStopSession` one. Nothing in Kairox retries a broadcast once a transaction has been signed; see [docs/security.md](security.md#uncertain-broadcast-handling).

## Recovery utilities

`.research/nft-public-mint` and `.research/osnm-z` are read-only reference implementations, used only to cross-check protocol behavior against real source when something in the SeaDrop/OpenSea integration needed independent verification (e.g. the EIP-712 domain, the exact allow-list leaf encoding, the aggregate-supply query safety argument in the security doc). Nothing in `src/` depends on them at build or run time, and `git diff -- .research` is expected to always be empty.

`testnet-lab/robinhood-testnet` is a separate, standalone Foundry project (its own `foundry.toml`/`lib/`) for deploying a disposable SeaDrop test collection on Robinhood Chain Testnet for acceptance testing -- it is not a Rust crate, is not part of the Cargo workspace, and nothing in `src/` depends on it at build or run time either. See [docs/robinhood-testnet-validation.md](robinhood-testnet-validation.md).
