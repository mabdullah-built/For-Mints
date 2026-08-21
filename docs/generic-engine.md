# Generic verified contract engine

`kairox mint --engine auto` can execute a conventional ERC-721/ERC-1155
mint the SeaDrop/OpenSea engines don't cover -- but only when the exact
mint call semantics are independently verified. It never tries a
plausible-looking selector and sends.

## Confidence model (corrected)

An earlier version of this pass treated an operator-declared
`--generic-schema` plus on-chain ERC-165 confirmation as sufficient for
`Confidence::High`. **That was wrong and has been corrected.** ERC-165
`supportsInterface` proves a contract implements the *NFT standard*
(ERC-721/ERC-1155) -- it proves nothing about which function mints, what
its arguments mean, whether it's payable, or what value it expects.
`mint(uint256,uint256)` could be `(tokenId, quantity)`, or just as
plausibly `(quantity, maxPrice)`, `(phaseId, quantity)`, or something else
entirely -- a matching signature alone doesn't resolve that ambiguity.

**`Confidence::High` now requires an exact
[`TrustedGenericFingerprint`](../src/execution/generic_registry.rs) match**:
the target's (proxy-resolved) implementation's runtime bytecode hash
exactly equals a manually-reviewed registry entry's. That entry alone
carries the real, verified mint semantics (selector, argument meanings,
payable, price) that get executed -- not the operator's schema.

`GenericVerifiedContractAdapter` (priority 2 -- tried only after native
SeaDrop and the OpenSea Drops route both miss):

1. Resolves the target's implementation address (following an EIP-1967
   proxy if present) and hashes its runtime bytecode
   (`execution::generic_engine::resolve_implementation_and_code_hash`).
2. Looks up `(chain_id, bytecode_hash)` in the trusted registry
   (`execution::generic_registry::find_fingerprint`). An exact match is
   `Confidence::High` and the *only* route to a live send.
3. If no registry match: an operator-declared `--generic-schema`
   (`OPERATOR_DECLARED_UNVERIFIED_SCHEMA`) plus ERC-165 confirmation is
   recorded as evidence, but is **always `Confidence::Low`**, regardless
   of whether ERC-165 returns `true`. Low confidence never resolves to a
   live-send path -- the resolver reports `UNSUPPORTED_PROTOCOL` with the
   low-confidence evidence included, so an operator can see *why*.

`BUILTIN_REGISTRY` ships **empty** -- no contract has been manually
reviewed and registered as part of this pass. That is the correct, honest
state: it means `mint --engine auto` currently has **no route to a real
generic live send at all**, anywhere, until either a real implementation
is reviewed and added to the registry, or a verified-ABI/explorer provider
integration (see Limitations) supplies equivalent independent evidence.
The full mechanism (exact match -> resolve -> prepare -> sign) is proven
by injecting a test fingerprint in `execution::generic_engine`'s unit
tests, since there's nothing in the shipped registry to exercise it
against end-to-end via the CLI.

An operator-supplied `--generic-schema`'s `price_per_token_wei`, even when
a registry match exists, is **never the source of truth** for what gets
signed -- it may only act as a maximum-price ceiling check against the
registry's verified price (`operator_max_price_per_token_wei` in
`GenericMintRequest`); if the verified price is higher, preparation
refuses.

## Trusted registry entries

```rust
TrustedGenericFingerprint {
    name: "...",                              // reporting label only
    chain_id: 4663,
    implementation_bytecode_hash: /* keccak256 of verified runtime bytecode */,
    standard: GenericStandard::Erc721,
    shape: GenericMintShape::MintQuantity,     // one of 4 fixed, reviewed shapes
    token_id: None,
    price_per_token_wei: 10_000_000_000_000_000,
}
```

`shape` selects one of exactly four fully-reviewed, tested calldata
builders (`execution::generic_engine::encode_calldata`) -- never a
parameter-position DSL Kairox interprets at runtime:

| shape | real signature |
|---|---|
| `mint_quantity` | `mint(uint256 quantity)` |
| `public_mint_quantity` | `publicMint(uint256 quantity)` |
| `mint_to_quantity` | `mint(address to, uint256 quantity)` |
| `mint_id_quantity` | `mint(uint256 id, uint256 quantity)` (ERC-1155) |

Adding a registry entry is a manual, reviewed act -- reading the actual
verified contract source, confirming the selector/argument/payable/price
semantics by hand, then adding a `TrustedGenericFingerprint` bound to that
exact implementation's bytecode hash. Adding a fifth calldata shape is a
separate code change (a new reviewed/tested match arm), not config.

## Proxy safety

A registry entry binds to an *implementation's* bytecode hash, not a
proxy's own (near-empty, delegate-only) bytecode. Detection resolves the
EIP-1967 implementation slot if present. **Immediately before every
signing**, `prepare_generic_transaction` re-resolves the implementation
and re-hashes its bytecode, and refuses (`PROXY_IMPLEMENTATION_CHANGED`)
if it no longer matches what was verified at resolution time -- a
compromised or legitimately-upgraded proxy between resolution and signing
can never cause Kairox to execute against unreviewed code. Tested with a
mocked implementation swap
(`proxy_implementation_changed_since_resolution_stops_before_signing`).

## Execution path

`execution::generic_engine::prepare_generic_transaction` mirrors
`execution::prepared::prepare_live_transaction`: pre-sign proxy re-check
(above), fresh nonce/fee/balance reads, `eth_estimateGas` as a preflight
(a revert is `DEFINITIVE_REVERT` and stops before signing), `SafetyCaps`
enforcement, sign, serialize. Broadcast (`execution::broadcast::broadcast_to_all`)
and receipt verification (`execution::receipt::poll_receipt` /
`protocol::logs::extract_minted_assets`) are the exact same,
already-hardened functions the SeaDrop PUBLIC engine uses --
`extract_minted_assets` now decodes both `TransferSingle` and
`TransferBatch` (ERC-1155), so a batch mint's receipt is verified too.

## Simulation taxonomy

`execution::generic_engine::SimulationOutcome` defines the full requested
taxonomy (`Pass`, `DefinitiveRevert`, `ExpectedPrestartRevert`,
`UnsupportedSimulation`), but only `Pass`/`DefinitiveRevert` are ever
actually produced this pass: nothing here independently establishes a
generic contract's stage timing, so there's no principled way to
distinguish "expected, still before start" from "genuinely broken" yet.
Every `eth_estimateGas` revert is treated as a live, definitive stop.

## Limitations (honest, not deferred silently)

- **`BUILTIN_REGISTRY` is empty.** No real contract has been manually
  reviewed and registered -- generic AUTO execution has no route to a
  live send in this build until an entry is added.
- **No verified-source/explorer API integration.** The only route besides
  the registry is ERC-165 + operator declaration, which is
  `Confidence::Low` and never sufficient. A real Etherscan/Blockscout
  "verified contract source" lookup is a separate, deliberately-deferred
  scope decision (new external API dependency, its own trust boundary,
  rate limits, legitimacy questions).
- **Not wired into `watch`.** There is no stage-timing concept for a
  generic contract (no equivalent of SeaDrop's on-chain
  `PublicDrop.startTime`) unless a future registry entry declares one, so
  `watch --engine auto` explicitly refuses a `Generic` resolution rather
  than guessing when to wait. Use `kairox mint` for an already-live
  generic contract.
- **No stage-aware simulation taxonomy in practice** (see above) --
  defined but unused pending a timing model.
- **Fixed set of four shapes.**
