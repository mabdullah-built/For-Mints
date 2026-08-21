# Generic verified contract engine

`kairox mint --engine auto --generic-schema <path>` can execute a
conventional ERC-721/ERC-1155 mint the SeaDrop/OpenSea engines don't cover
-- but only when the exact mint call semantics are known with high
confidence. It never tries a plausible-looking selector and sends.

## Two-factor activation

`GenericVerifiedContractAdapter` (priority 2 -- tried only after native
SeaDrop and the OpenSea Drops route both miss) requires **both**:

1. **An operator-declared schema** (`--generic-schema schema.toml`) --
   never invented by Kairox. This is the "explicit trusted adapter schema"
   form of evidence: the operator has independently verified (read the
   contract source themselves, checked a block explorer's "Read/Write
   Contract" tab, etc.) that this schema is correct for this specific
   contract, and told Kairox so.
2. **On-chain ERC-165 corroboration**: `supportsInterface` for the
   schema's declared standard (`0x80ac58cd` for ERC-721, `0xd9b67a26` for
   ERC-1155) must return `true`, read fresh from the chain
   (`protocol::erc_standards`).

Either alone is `Confidence::Low` and resolves to `UNSUPPORTED_PROTOCOL`,
never a live-send path -- an operator schema for a contract that doesn't
actually implement the declared standard, or a confirmed-standard contract
nobody described a schema for, are both refused.

## Schema (`--generic-schema`)

```toml
standard = "erc721"          # or "erc1155"
shape = "mint_quantity"      # mint_quantity | public_mint_quantity | mint_to_quantity | mint_id_quantity
token_id = 42                # required only for mint_id_quantity
price_per_token_wei = "10000000000000000"
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

`price_per_token_wei * quantity` is the transaction's exact `value` --
Kairox has no standard price getter to trust for an arbitrary contract, so
this is operator-declared too.

## Execution path

`execution::generic_engine::prepare_generic_transaction` mirrors
`execution::prepared::prepare_live_transaction` exactly: fresh nonce/fee/
balance reads, `eth_estimateGas` as a preflight (a revert here is
`DEFINITIVE_REVERT` and stops before signing -- there is no stage-timing
model in this pass to excuse it as "not open yet", see Limitations),
`SafetyCaps` enforcement, sign, serialize. Broadcast
(`execution::broadcast::broadcast_to_all`) and receipt verification
(`execution::receipt::poll_receipt` /
`protocol::logs::extract_minted_assets`) are the exact same,
already-hardened, already-generic functions the SeaDrop PUBLIC engine
uses -- both were standard-agnostic (`Transfer`/`TransferSingle`) before
this pass and needed zero changes.

## Limitations (honest, not deferred silently)

- **Not wired into `watch`.** There is no stage-timing concept for a
  generic contract (no equivalent of SeaDrop's on-chain `PublicDrop.startTime`),
  so `watch --engine auto` explicitly refuses a `Generic` resolution rather
  than guessing when to wait. Use `kairox mint` for an already-live generic
  contract.
- **No `TransferBatch` decoding.** `extract_minted_assets` handles
  `Transfer` (ERC-721) and `TransferSingle` (ERC-1155), not `TransferBatch`
  -- a batch ERC-1155 mint's receipt truth isn't verified by this pass.
- **No stage-aware simulation taxonomy.** Only `PASS`/`DEFINITIVE_REVERT`
  exist here; `EXPECTED_PRESTART_REVERT`/`UNSUPPORTED_SIMULATION` (from the
  fuller taxonomy sketched for `watch`) would require a timing model this
  engine doesn't have.
- **No verified-source/explorer API integration.** Detection is ERC-165 +
  operator declaration only -- no Etherscan/Blockscout "verified contract
  source" lookup. Adding one is a real, separate scope decision (a new
  external API dependency, its own trust boundary, rate limits, and
  legitimacy questions) deliberately not made in this pass.
- **No proxy-aware re-detection.** `protocol::erc_standards::eip1967_implementation`
  exists and is tested, but nothing currently calls it during resolution --
  `supportsInterface` against the proxy address already reflects the
  implementation's behavior (proxies delegate calls transparently), so
  detection is correct without it; it's there for future evidence
  reporting (e.g. showing the resolved implementation address), not yet
  wired into `ProtocolEvidence`.
- **Fixed set of four shapes.** Adding a fifth is a code change (a new
  reviewed/tested match arm), not a config-only addition -- deliberately,
  so nothing here becomes a runtime-interpreted calldata template.
