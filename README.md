# Kairox

Kairox is an independently-implemented, low-latency command-line tool for executing SeaDrop NFT mints: pure on-chain public mints, and OpenSea-hosted wallet-specific/allowlist/server-signed mints. It supports both single-wallet and self-funded multi-wallet sessions.

**Kairox is dry-run by default.** No command ever broadcasts a transaction unless you explicitly pass `--send` to `kairox mint` (plus confirmation).

## What Kairox is not

Kairox does not fund wallets, generate wallets, sweep/withdraw funds, sponsor gas, use EIP-7702, or attempt to evade any protocol's per-wallet mint limits. It only signs and broadcasts with a private key you already control, for a quantity a project's own contract/API already allows that wallet.

## Supported chains

| Chain | Chain ID |
|---|---|
| Ethereum | 1 |
| Base | 8453 |
| Robinhood Chain | 4663 |

Any other chain works too if you pass `--seadrop-contract` explicitly (Kairox only ships a default SeaDrop address for the three above).

## Supported mint paths

- **Pure on-chain public mint** (`--engine public`): reads a collection's `PublicDrop` config directly from its SeaDrop contract, builds and signs a `mintPublic` transaction locally. No third-party API involved.
- **OpenSea-hosted mint** (`--engine opensea`, requires `--slug`): fetches wallet-specific mint calldata from the official OpenSea Drops API (public, allowlist, or server-signed stages), verifies it locally against on-chain state before ever signing it (Merkle proof recomputation, EIP-712 signature recovery, on-chain simulation), then signs and broadcasts.
- **`--engine auto`** (the default): picks `public` if the public stage is currently active and plannable, otherwise falls back to `opensea` (only when `--slug` is given).
- **Multi-wallet sessions** (`--wallet-manifest FILE`): the same mint, run for up to 50 self-funded wallets from one process, with an aggregate spend/supply preflight before any wallet is signed.

## Installation / build

Requires a recent stable Rust toolchain (edition 2024).

```sh
cargo build --release
./target/release/kairox --version
```

## Configuration

Kairox runs with zero configuration by default — every setting has a compiled-in default, and RPC/OpenSea credentials come from environment variables. An optional TOML config file lets you set per-machine defaults without repeating `--chain`/`--rpc-url` on every command, but **it only ever names environment variables, never a secret value**:

```sh
kairox init                     # writes ~/.config/kairox/config.toml
kairox init --path ./kairox.toml --force
```

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

Loading a config file where a `*_env` field looks like a pasted secret (long hex, or a multi-word mnemonic) fails closed rather than accepting it.

**Config file location precedence:** `--config PATH` > `KAIROX_CONFIG` env var > `~/.config/kairox/config.toml` (only if it already exists).

**Setting precedence** (chain, engine, RPC endpoints): explicit CLI flag > environment variable (`KAIROX_CHAIN`/`KAIROX_ENGINE`) > config file `[defaults]`/`[chains.*]` > compiled default. This is decided in exactly one place (`config::resolve_runtime_config`) and used by every network-touching command.

Environment variables Kairox reads directly (never in the config file):

| Variable | Purpose |
|---|---|
| `KAIROX_RPC_<chainId>_<n>_URL` | RPC endpoint URL (indexed, `_0_`, `_1_`, ...) |
| `KAIROX_RPC_<chainId>_<n>_ROLE` | `READ_WRITE`/`READ_ONLY`/`SEND_ONLY`/`SEQUENCER`/`PRIVATE`/`PUBLIC` |
| `KAIROX_RPC_<chainId>_<n>_LABEL` / `_TIMEOUT_MS` | optional label / per-endpoint timeout |
| `KAIROX_SIGNING_KEY` | hex private key (only read when `--send` actually signs; interactive prompt otherwise) |
| `KAIROX_OPENSEA_API_KEY` | OpenSea Drops API key (only read for `--engine opensea`) |
| `KAIROX_CHAIN` / `KAIROX_ENGINE` | override the resolved chain/engine default |
| `KAIROX_CONFIG` | explicit config file path |

## Commands

```
kairox doctor [--json]                 # environment/config/endpoint health check
kairox inspect <collection> [--wallet W] [--slug SLUG]
kairox plan <collection> --wallet W [--json] [--output PATH]
kairox mint <collection> --wallet W [--send [--yes]] [--json] [--output PATH]
kairox mint <collection> --wallet-manifest FILE --send --engine public|opensea
kairox bench [--chain C]
kairox init [--path PATH] [--force]
kairox receipt --tx H --collection C --wallet W [--json]
```

Every command's exact flags are documented via `--help`; the shapes above are the common cases. Global `--config PATH` works on every subcommand.

### `kairox doctor`

Environment/config preflight. Reports Kairox version, OS, UTC time, whether a signing key / OpenSea key is configured (presence only, never the value), config file status, and per-chain RPC connectivity. `--json` emits one JSON object on stdout; diagnostics never mix into it.

### `kairox inspect <collection>`

Read-only, normalized view of a SeaDrop collection's current on-chain public-stage config, supply, and (with `--slug`) OpenSea's off-chain metadata — clearly labeled as informational, never treated as stronger than the on-chain state.

### `kairox plan <collection> --wallet W`

Builds and prints the authoritative dry-run plan for a public mint: fee recipient, mint value, worst-case gas/spend, calldata, stage window and status. `--json`/`--output PATH` emit a structured `ExecutionPlanReport` with a deterministic `plan_id` (see [docs/architecture.md](docs/architecture.md#plan_id)).

### `kairox mint <collection> --wallet W`

Dry-run by default (identical output shape to `plan`, for whichever engine `--engine`/`--slug` resolves to). `--send` opts into the live pipeline: a confirmation summary, signing-key load, scheduled pre-signing, identical-raw-transaction broadcast to every send-capable endpoint, and receipt verification. `--json`/`--output PATH` emit a `SessionReport` with a `session_id` generated before any signing.

### `kairox mint <collection> --wallet-manifest FILE --engine public|opensea --send`

Runs the same mint for every wallet in a JSON manifest (up to 50), with a bounded concurrency for both broadcast dispatch and (for the OpenSea engine) API requests, an aggregate spend/stage-supply preflight before any wallet is signed, and a deterministic manifest-order result set. `--engine auto` is not supported in manifest mode — pick `public` or `opensea` explicitly. `--json`/`--output PATH` emit the same `SessionReport` schema as a single-wallet session, with one `WalletReport` per manifest entry in manifest order (dry-run or live, for both engines) — proven end-to-end in `tests/e2e_localhost.rs`.

### `kairox bench`

Connects to and benchmarks every configured endpoint for a chain (latency, role, selection outcome). Never signs or broadcasts.

### `kairox receipt --tx H --collection C --wallet W`

Read-only recheck of a transaction's receipt: confirms it landed, and independently verifies the expected mint `Transfer` event(s) from the collection contract — never trusts broadcast acceptance or receipt status alone as proof of a successful mint. Never resubmits anything.

## Uncertain transactions

If a broadcast's outcome cannot be determined (a timeout or connection failure with no response), Kairox reports the wallet as **Uncertain** and never automatically retries or replaces it with a new signature — retrying an unknown-outcome broadcast risks a double-send. If this happens, wait, then use `kairox receipt` to check the actual on-chain outcome once you have a tx hash (or once one appears) — see [docs/security.md](docs/security.md) for the full procedure.

## JSON output and error codes

`doctor`, `plan`, `mint` (single-wallet and `--wallet-manifest`), and `receipt` support `--json`: stdout carries exactly one JSON object and nothing else; all progress/diagnostic text goes to stderr. Every report starts with `schema_version`. Every CLI error is printed as `error[CODE]: message` on stderr with a stable `KairoxErrorCode` (`CONFIG_INVALID`, `CHAIN_MISMATCH`, `OPENSEA_AUTH_FAILED`, `RECEIPT_MINT_MISMATCH`, `WALLET_KEY_MISMATCH`, `INSUFFICIENT_BALANCE`, `SESSION_CAP_EXCEEDED`, `NO_VERIFIED_READ_RPC`, etc.) — see [docs/architecture.md](docs/architecture.md).

## Security model

See [docs/security.md](docs/security.md) for the full model: key handling, secret redaction, uncertain-broadcast policy, receipt truth, and what Kairox explicitly refuses to do.

## Known limitations

- `--json`/`--output` for a dry-run `mint --engine opensea` is not implemented (the OpenSea dry-run preview only fetches informational drop metadata, not a validated plan — producing one would require the same wallet-specific mint-transaction request `--send` makes, which is not something a "dry run" should trigger against a third-party API) — it fails closed with a clear error rather than emitting an incomplete report. Live `--send` with `--engine opensea` (single- or multi-wallet) does emit the full `SessionReport`.
- No Ctrl-C/SIGINT handling: killing the process mid-broadcast does not tell you whether the transaction was actually sent — treat an interrupted `--send` the same as an Uncertain outcome and check `kairox receipt` once you have a chance. No background task outlives the process either way (see [docs/architecture.md](docs/architecture.md) for the no-detached-task audit): there is nothing left running after an interrupt, only genuine uncertainty about what the remote node did with bytes already sent.
- No `kairox receipt --report FILE` batch-recheck command; recheck one transaction at a time with `kairox receipt --tx ... --collection ... --wallet ... --quantity ...`.
- No shell completions yet.
- No telemetry of any kind — but see the Privacy section in [docs/security.md](docs/security.md) for what your RPC provider and OpenSea itself can see.

## End-to-end test coverage

`tests/e2e_localhost.rs` runs the actual compiled `kairox` binary as a subprocess against a real, hand-rolled `std::net::TcpListener` HTTP/1.1 server (not a mocked transport trait) — the real `reqwest`-based RPC and OpenSea HTTP clients genuinely connect over a loopback socket. It covers: public single- and multi-wallet dry-run and live mints; OpenSea allowlist and server-signed mints with real locally-generated Merkle proofs and EIP-712 signatures; OpenSea 401/403/422/429/500 responses and malicious-response rejection (bad proof, bad signature, wrong collection, unsupported selector) before any Ethereum signature; a genuine possible-send broadcast (the server reads the full raw transaction, then closes the connection with no response) proven Uncertain, never retried; definitive broadcast rejection; receipt revert and four receipt/mint-mismatch shapes; JSON stdout purity and `--output` file writes for every JSON-capable command; config precedence and malformed/invalid config; and secret-redaction across successful and failing real-HTTP paths. No test in this file broadcasts to a real chain.

## Documentation

- [docs/security.md](docs/security.md) — key handling, redaction, uncertain-broadcast policy, receipt truth, privacy
- [docs/architecture.md](docs/architecture.md) — module layout, execution pipeline, report schemas
- [docs/operator-guide.md](docs/operator-guide.md) — a full walkthrough: init → doctor → inspect → plan → mint

## Reference material

`.research/` contains third-party reference implementations, kept strictly read-only and used only to cross-check protocol behavior (calldata shapes, EIP-712 domains, error semantics) against the real `ProjectOpenSea/seadrop` contracts. It is not part of the Kairox source tree and nothing in `src/` depends on it at build time.
