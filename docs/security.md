# Security model

## Private key lifetime

A signing key is loaded exactly once per `--send` session, from `KAIROX_SIGNING_KEY` (hex, with or without `0x` prefix) or an interactive prompt if that variable is unset. It is:

- Never read for a dry run (`kairox plan`, `kairox mint` without `--send`) — those paths never touch `KAIROX_SIGNING_KEY` at all.
- Never logged, printed, or included in any error message, `Debug` output, or JSON report. `LocalSigner`'s `Debug` implementation is written to guarantee this (see `signing::signer` tests).
- Verified against the wallet address you passed (`--wallet`) before anything is signed — if the loaded key resolves to a different address, Kairox refuses to proceed rather than silently signing with the "wrong" key.
- Zeroized on drop (`zeroize` crate) once the session ends.

For a multi-wallet manifest, each wallet's key comes from its own named environment variable (`key_env` in the manifest, never a literal key in the manifest file itself) and is verified to resolve to that wallet's declared address before it is used.

## Config file secrets

The optional TOML config file (`kairox init`, `--config`, `KAIROX_CONFIG`) only ever names environment variables — `read_rpc_env`, `send_rpc_env`, `api_key_env` — never a secret value. Loading a config file fails closed if any of those fields looks like a secret was pasted in directly (long hex ≥32 characters, or ≥8 space-separated words resembling a BIP-39 mnemonic). This is a heuristic, not a guarantee — it catches the common mistake, not every possible way to paste a secret into the wrong field.

## OpenSea API key handling

`KAIROX_OPENSEA_API_KEY` is read only when the OpenSea engine is actually used. It is sent as the API's documented header on every request and never logged; `opensea::client` tests assert it never appears in any constructed error message, including ones built from server response bodies.

## RPC credential redaction

Any RPC URL with embedded HTTP basic-auth credentials (`https://user:pass@host/...`) or a query-string token has both stripped before the URL is ever displayed (`kairox doctor`, `kairox bench`) — `cli::format::mask_url` clears the URL's userinfo and replaces its query string with `REDACTED`.

This redaction only covers Kairox's own *display* of a URL. A separate, previously-undiscovered leak existed in the underlying transport error path: `reqwest::Error`'s `Display`/`to_string()` embeds the full request URL, credentials included, so a connection failure against a misconfigured or dead endpoint used to leak that URL verbatim into `TransportError::Network` and onward into `doctor` output and propagated errors. This was found by an adversarial test (planting sentinel "secret" strings in an RPC URL's userinfo and query string, then asserting they never appear in the real binary's stdout/stderr) and fixed by describing transport errors from the error's underlying cause (`source()`) rather than its top-level `Display`, which never includes the request URL. See `tests/cli_surface.rs`'s `*_never_leaks_any_adversarial_sentinel` tests, which still run this exact check today.

## Signed transaction semantics

Kairox signs exactly one transaction per wallet per attempt, once. The raw signed bytes and pre-hex-encoded `eth_sendRawTransaction` request body are built once and reused byte-for-byte across every send-capable endpoint (`execution::prepared`/`execution::broadcast`) — there is never a second signature for the same intended mint, and a slow or partially-failing endpoint never triggers a re-sign.

`kairox mint --json`/`--output` never persists the raw signed transaction — only its resulting hash, once broadcast. There is no code path anywhere in Kairox that writes a raw signed transaction to disk.

## Uncertain broadcast handling

An endpoint's broadcast outcome is one of: `Accepted`/`AlreadyKnown` (propagation evidence), a definite rejection (`FatalRejection`/`RetryableRejection` — external code `BROADCAST_FATAL`), or genuinely unknown (`TimeoutUnknown`/`TransportUnknown` — external code `BROADCAST_UNCERTAIN`, when no endpoint gave a definite answer either way).

**Kairox never automatically retries or re-signs an Uncertain broadcast.** Retrying with a fresh signature for the same nonce risks a double-send if the original transaction actually did land; retrying with a bumped nonce risks abandoning a transaction that will still confirm. If a session reports Uncertain: stop, wait, and use `kairox receipt --tx <hash-if-you-have-one> --collection C --wallet W` to check the real on-chain outcome once you're able to. If you never received a tx hash at all (the signing/serialization step itself was interrupted), there is nothing to recheck — no transaction was ever produced.

## Receipt truth

A transaction receipt's `status == 1` (success) is never, on its own, treated as proof a mint succeeded — only as proof the transaction executed without reverting. `execution::receipt::poll_receipt` additionally decodes the collection contract's own `Transfer` event log(s) and requires exactly the expected quantity of unique-token-id mint transfers (`from == 0x0`, `to == wallet`) before reporting `CONFIRMED_SUCCESS`. A successful-but-mismatched receipt is reported as `CONFIRMED_EXECUTION_MISMATCH` (external code `RECEIPT_MINT_MISMATCH`) — blockchain execution is confirmed, but the expected mint evidence was not found, and this is always terminal: it must never be treated as network-uncertain, since the transaction definitely executed.

## Multi-wallet policy

- Self-funded only. Kairox never funds, sweeps, or moves value between wallets in a manifest.
- Every wallet's key must independently resolve to its declared address; a mismatch fails only that wallet, never the whole session.
- An aggregate preflight (spend cap, and — for OpenSea sessions with a stage-supply constraint — remaining collection supply) runs once, against the whole eligible wallet set, before any wallet is signed. This closes a real race that existed earlier in development: signing wallets as their individual OpenSea responses arrived, before every wallet's stage constraint was known, could let an early wallet's mint push the collection past a later wallet's now-violated stage-supply ceiling. The aggregate check is a no-op (zero added latency) when no session cap or stage constraint applies.

## Stage-supply aggregation

The aggregate stage-supply check reads `currentTotalSupply`/`maxSupply` via `getMintStats(Address::ZERO)` — a protocol-safe query, since those two fields are collection-wide facts independent of which minter address is queried (only `minterNumMinted` varies with the queried address, per the SeaDrop contract source). This was verified directly against the current `ProjectOpenSea/seadrop` GitHub source, not assumed from memory.

## No funding, no limit bypass

Kairox has no code path that funds a wallet, generates a wallet, sweeps or withdraws value, sponsors another wallet's gas, uses EIP-7702, or attempts to mint more than a wallet's own on-chain/API-reported allocation permits. It only signs and sends what the target contract or API already allows the specified wallet to do.

## Known limitations (security-relevant)

- **No Ctrl-C/SIGINT handling.** Interrupting a `--send` session does not tell you whether the in-flight transaction was actually broadcast. Treat an interrupted session exactly like an Uncertain outcome: don't assume it was cancelled, and check `kairox receipt` once you can.
- **SessionError lacks a structured error-code field.** Several outcomes (wallet-key mismatch, insufficient balance, session-cap exceeded) currently surface through a free-text `SessionError` message rather than a dedicated `KairoxErrorCode` variant — the code falls back to `SESSION_ABORTED` for these. The message text itself is still accurate and specific; only the *machine-readable code* is coarser than ideal for these cases.
- No `cargo audit` was run as part of this hardening pass — it is not installed in this environment and was not installed solely to run it once.

## Privacy

Kairox itself sends no telemetry anywhere. It has no analytics, no phone-home, no update check.

That said, Kairox is a thin client over other people's infrastructure, and using it means those services see what any client using them would see:

- Your configured **RPC provider** sees every request Kairox makes on your behalf — including the wallet addresses you query or mint from, and (for a live send) the raw signed transaction before it reaches the chain.
- **OpenSea** sees every request Kairox makes to its Drops API when you use `--engine opensea` — the minter address, quantity, and collection you're interacting with.

Kairox does not, and cannot, hide your activity from the providers you've configured it to talk to.
