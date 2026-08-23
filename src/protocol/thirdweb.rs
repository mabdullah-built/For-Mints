//! Independent local encoding/decoding of thirdweb's Drop claim ABIs.
//!
//! **CORRECTION (Phase B correctness gate)**: an earlier version of this
//! module claimed `Drop`, `DropSinglePhase`, and their ERC-1155
//! counterparts "share the identical claim/ClaimCondition/AllowlistProof
//! interface". That was wrong, and was corrected after re-reading the
//! actual official source (not a search-result summary) rather than
//! assuming one thirdweb flavor's ABI generalizes to the others. Four
//! distinct, source-verified shapes exist -- see [`ThirdwebFlavor`]:
//!
//! - **Multi-phase ERC-721** (`contracts/extension/Drop.sol`,
//!   `IClaimConditionMultiPhase`): `getActiveClaimConditionId() -> uint256`,
//!   `getClaimConditionById(uint256 conditionId) -> ClaimCondition`,
//!   `getSupplyClaimedByWallet(uint256 conditionId, address claimer) -> uint256`
//!   (the wallet counter is keyed *by condition id*).
//! - **Single-phase ERC-721** (`contracts/extension/DropSinglePhase.sol`):
//!   a single public state variable `ClaimCondition public claimCondition;`
//!   (auto-generated no-argument getter -- **not** `getClaimConditionById`),
//!   and `getSupplyClaimedByWallet(address claimer) -> uint256` (**one**
//!   argument -- no `conditionId` exists in this flavor's ABI at all; an
//!   earlier version of this module called the two-argument multi-phase
//!   selector unconditionally, which would target the wrong function
//!   entirely against a real `DropSinglePhase` deployment). The `claim()`
//!   calldata shape is identical to the multi-phase ERC-721 flavor.
//! - **Single-phase ERC-1155** (`contracts/extension/DropSinglePhase1155.sol`):
//!   `mapping(uint256 => ClaimCondition) public claimCondition;` (takes
//!   `tokenId`), `getSupplyClaimedByWallet(uint256 tokenId, address claimer) -> uint256`.
//!   `claim()` takes an extra leading `tokenId`. **Not yet wired into any
//!   execution path** -- see [`ThirdwebFlavor`]'s doc comment.
//! - **Multi-phase ERC-1155** (`contracts/extension/Drop1155.sol`):
//!   `getActiveClaimConditionId(uint256 tokenId) -> uint256`,
//!   `getClaimConditionById(uint256 tokenId, uint256 conditionId) -> ClaimCondition`,
//!   `getSupplyClaimedByWallet(uint256 tokenId, uint256 conditionId, address claimer) -> uint256`.
//!   **Not yet wired into any execution path.**
//!
//! Every signature above was verified directly against the official
//! `thirdweb-dev/contracts` repository source files named. Kairox never
//! asks any third-party API for this calldata or for merkle-proof
//! verification; the interface is fixed, well-known, and encoded/decoded
//! here directly -- but *which* interface a given deployed contract
//! actually implements is never assumed from one flavor onto another.
//! See [`ThirdwebFlavor::detect`] (`execution::thirdweb_engine`) for how
//! Kairox determines which flavor a specific address implements before
//! calling any flavor-specific getter.
//!
//! Scope of this module (v0.8 Phase B): native-currency claims only.
//! `currency` fields other than [`NATIVE_TOKEN`] are surfaced but never
//! authorize a value derivation here -- ERC20-priced NFT mints are explicit
//! future scope (deferred to a later phase alongside broader ERC20-payment
//! support), never silently guessed at.

use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy_sol_types::{SolCall, sol};
use thiserror::Error;

sol! {
    #[derive(Debug)]
    // Verified against thirdweb-dev/contracts `contracts/extension/Drop.sol`
    // and `contracts/extension/interface/IDropSinglePhase.sol`.
    struct ClaimConditionAbi {
        uint256 startTimestamp;
        uint256 maxClaimableSupply;
        uint256 supplyClaimed;
        uint256 quantityLimitPerWallet;
        bytes32 merkleRoot;
        uint256 pricePerToken;
        address currency;
        string metadata;
    }

    #[derive(Debug)]
    struct AllowlistProofAbi {
        bytes32[] proof;
        uint256 quantityLimitPerWallet;
        uint256 pricePerToken;
        address currency;
    }

    // --- Multi-phase ERC-721 (Drop.sol / IClaimConditionMultiPhase) ---
    function getActiveClaimConditionId() external view returns (uint256);
    function getClaimConditionById(uint256 conditionId) external view returns (ClaimConditionAbi memory);
    function getSupplyClaimedByWallet(uint256 conditionId, address claimer) external view returns (uint256);

    // --- Single-phase ERC-721 (DropSinglePhase.sol) ---
    // `claimCondition` is a public state variable of type `ClaimCondition`
    // (not a mapping) -- Solidity auto-generates a no-argument getter for
    // it, with the exact same selector `claimCondition()` always has.
    function claimCondition() external view returns (ClaimConditionAbi memory);

    // Identical signature shared by the multi-phase (`Drop`) and
    // single-phase (`DropSinglePhase`) extensions, and by both the
    // ERC-721 and ERC-1155 variants (the 1155 claim additionally takes a
    // leading `tokenId`, encoded separately below as `claim1155`).
    function claim(
        address receiver,
        uint256 quantity,
        address currency,
        uint256 pricePerToken,
        AllowlistProofAbi calldata allowlistProof,
        bytes memory data
    ) external payable;

    // ERC-1155 variant: `contracts/extension/DropSinglePhase1155.sol` /
    // the multi-phase 1155 equivalent -- one extra leading `tokenId`
    // argument, otherwise identical.
    function claim1155(
        address receiver,
        uint256 tokenId,
        uint256 quantity,
        address currency,
        uint256 pricePerToken,
        AllowlistProofAbi calldata allowlistProof,
        bytes memory data
    ) external payable;
}

// Isolated scope: `DropSinglePhase.sol`'s `getSupplyClaimedByWallet(address)`
// has the SAME on-chain function name as the multi-phase two-argument
// getter above, but a genuinely different selector (Solidity selectors
// are computed from the full signature, including argument types) --
// `alloy_sol_types::sol!` would otherwise generate a colliding Rust type
// name (`getSupplyClaimedByWalletCall`) for both. Scoping this one in its
// own module (mirroring `generic_engine::encode_calldata`'s identical
// technique for the same underlying reason) keeps the on-chain function
// name and selector exactly correct while giving Rust a distinct type
// (`single_phase::getSupplyClaimedByWalletCall`).
pub mod single_phase {
    use alloy_sol_types::sol;

    sol! {
        function getSupplyClaimedByWallet(address claimer) external view returns (uint256);
    }
}

/// The sentinel address thirdweb (and most EVM protocols) use to mean
/// "pay in the chain's native currency" rather than an ERC-20 token --
/// verified against thirdweb's own documented example allowlist-proof
/// payload (`"currency": "0xeeee...eeee"`).
pub const NATIVE_TOKEN: Address = address!("EeeeeEeeeEeEeeEeEeEeeeEeeeeEeeeeEeeeeeEE");

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThirdwebError {
    #[error("nft contract address must not be the zero address")]
    ZeroNftContract,
    #[error("startTimestamp/endTimestamp does not fit safely in a u64 conversion")]
    TimestampOverflow,
    #[error(
        "maxClaimableSupply/supplyClaimed/quantityLimitPerWallet does not fit safely in a u64 conversion"
    )]
    SupplyOverflow,
    #[error("failed to decode ABI return data: {0}")]
    AbiDecode(String),
    #[error(
        "claim condition pays in ERC-20 currency {0:#x}, not the native token; ERC20-priced \
         thirdweb mints are not yet supported"
    )]
    Erc20CurrencyUnsupported(Address),
}

/// Normalized, validated `ClaimCondition` state for one phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimCondition {
    pub start_timestamp: u64,
    pub max_claimable_supply: U256,
    pub supply_claimed: U256,
    pub quantity_limit_per_wallet: U256,
    pub merkle_root: B256,
    pub price_per_token: U256,
    pub currency: Address,
}

impl ClaimCondition {
    pub(crate) fn from_abi(abi: ClaimConditionAbi) -> Result<Self, ThirdwebError> {
        Ok(Self {
            start_timestamp: abi
                .startTimestamp
                .try_into()
                .map_err(|_| ThirdwebError::TimestampOverflow)?,
            max_claimable_supply: abi.maxClaimableSupply,
            supply_claimed: abi.supplyClaimed,
            quantity_limit_per_wallet: abi.quantityLimitPerWallet,
            merkle_root: abi.merkleRoot,
            price_per_token: abi.pricePerToken,
            currency: abi.currency,
        })
    }

    /// `true` only when this condition pays in the chain's native
    /// currency -- the only case this module's calldata/value derivation
    /// currently supports. Never inferred from anything but the exact
    /// sentinel address thirdweb itself documents.
    pub fn is_native_currency(&self) -> bool {
        self.currency == NATIVE_TOKEN
    }

    /// `maxClaimableSupply - supplyClaimed`, exactly as `Drop.sol`'s own
    /// `verifyClaim` enforces it (`supplyClaimed + quantity >
    /// maxClaimableSupply` reverts) -- verified directly against source:
    /// there is **no** "`maxClaimableSupply == 0` means unlimited"
    /// special case in the real contract (an earlier draft of this
    /// module assumed one, sourced only from a secondary summary, and
    /// was corrected after reading `Drop.sol` itself). A `0` cap
    /// genuinely means nobody can claim under this phase, exactly like
    /// any other exhausted-supply state.
    pub fn supply_remaining(&self) -> U256 {
        self.max_claimable_supply
            .saturating_sub(self.supply_claimed)
    }

    /// A stable fingerprint of this condition's execution-affecting
    /// configuration -- `start_timestamp`, `max_claimable_supply`,
    /// `quantity_limit_per_wallet`, `merkle_root`, `price_per_token`,
    /// `currency`. Deliberately EXCLUDES `supply_claimed`, which
    /// increments with every mint and is never grounds for treating a
    /// watched condition as "changed" -- only the operator-configured
    /// terms matter here. Two reads of a condition that returns the same
    /// fingerprint were configured identically, regardless of how many
    /// tokens were claimed in between; a changed fingerprint means the
    /// creator materially reconfigured this condition id (thirdweb's
    /// `updateClaimConditions` can rewrite a condition's terms in place
    /// without changing its id when eligibility is not reset) and a
    /// `watch` attempt targeting it must stop rather than sign against
    /// silently different terms.
    pub fn config_fingerprint(&self) -> B256 {
        let mut buf = Vec::with_capacity(32 * 6);
        buf.extend_from_slice(&self.start_timestamp.to_be_bytes());
        buf.extend_from_slice(&self.max_claimable_supply.to_be_bytes::<32>());
        buf.extend_from_slice(&self.quantity_limit_per_wallet.to_be_bytes::<32>());
        buf.extend_from_slice(self.merkle_root.as_slice());
        buf.extend_from_slice(&self.price_per_token.to_be_bytes::<32>());
        buf.extend_from_slice(self.currency.as_slice());
        keccak256(buf)
    }
}

/// Build the calldata for `getActiveClaimConditionId()`.
pub fn encode_get_active_claim_condition_id() -> Bytes {
    Bytes::from(getActiveClaimConditionIdCall {}.abi_encode())
}

/// Decode the return data of `getActiveClaimConditionId()`.
pub fn decode_get_active_claim_condition_id(data: &[u8]) -> Result<U256, ThirdwebError> {
    getActiveClaimConditionIdCall::abi_decode_returns(data)
        .map_err(|e| ThirdwebError::AbiDecode(e.to_string()))
}

/// Build the calldata for `getClaimConditionById(uint256)`.
pub fn encode_get_claim_condition_by_id(condition_id: U256) -> Bytes {
    Bytes::from(
        getClaimConditionByIdCall {
            conditionId: condition_id,
        }
        .abi_encode(),
    )
}

/// Decode the return data of `getClaimConditionById(uint256)`.
pub fn decode_get_claim_condition_by_id(data: &[u8]) -> Result<ClaimCondition, ThirdwebError> {
    let decoded = getClaimConditionByIdCall::abi_decode_returns(data)
        .map_err(|e| ThirdwebError::AbiDecode(e.to_string()))?;
    ClaimCondition::from_abi(decoded)
}

/// Build the calldata for `getSupplyClaimedByWallet(uint256, address)`.
/// Verified directly against the real `Drop.sol` source (not merely its
/// summarized documentation, which omitted the leading `conditionId`
/// parameter): the counter is keyed per claim-condition id, so a
/// wallet's allocation genuinely resets at each new phase -- never a
/// lifetime-cumulative counter.
pub fn encode_get_supply_claimed_by_wallet(condition_id: U256, claimer: Address) -> Bytes {
    Bytes::from(
        getSupplyClaimedByWalletCall {
            conditionId: condition_id,
            claimer,
        }
        .abi_encode(),
    )
}

/// Decode the return data of `getSupplyClaimedByWallet(uint256, address)`.
pub fn decode_get_supply_claimed_by_wallet(data: &[u8]) -> Result<U256, ThirdwebError> {
    getSupplyClaimedByWalletCall::abi_decode_returns(data)
        .map_err(|e| ThirdwebError::AbiDecode(e.to_string()))
}

/// Build the calldata for `claimCondition()` -- `DropSinglePhase.sol`'s
/// public state-variable getter (single-phase ERC-721 flavor only).
pub fn encode_claim_condition_single_phase() -> Bytes {
    Bytes::from(claimConditionCall {}.abi_encode())
}

/// Decode the return data of `claimCondition()`.
pub fn decode_claim_condition_single_phase(data: &[u8]) -> Result<ClaimCondition, ThirdwebError> {
    let decoded = claimConditionCall::abi_decode_returns(data)
        .map_err(|e| ThirdwebError::AbiDecode(e.to_string()))?;
    ClaimCondition::from_abi(decoded)
}

/// **CORRECTION**: `claimCondition()` is not single-phase-exclusive.
/// `Drop.sol` (multi-phase) *also* declares `ClaimConditionList public
/// claimCondition;` -- verified against
/// `contracts/extension/interface/IDrop.sol`'s real struct:
/// ```solidity
/// struct ClaimConditionList {
///     uint256 currentStartId;
///     uint256 count;
///     mapping(uint256 => ClaimCondition) conditions;
///     mapping(uint256 => mapping(address => uint256)) supplyClaimedByWallet;
/// }
/// ```
/// Solidity's auto-generated public getter for a struct silently omits
/// mapping fields, so the multi-phase contract's `claimCondition()`
/// returns only `(uint256 currentStartId, uint256 count)` -- the exact
/// same selector as the single-phase getter above, but a genuinely
/// different, much shorter return shape. An earlier version of this
/// module used `getActiveClaimConditionId()`/`active_id + 1` as the
/// multi-phase enumeration anchor; that is insufficient (it reverts
/// before any phase has started, exactly when discovering an
/// upcoming multi-phase drop for `watch` matters most) and has been
/// replaced by reading this authoritative `(currentStartId, count)`
/// pair directly -- see `decode_claim_condition_list`.
pub mod multi_phase_list {
    use alloy_sol_types::sol;

    sol! {
        function claimCondition() external view returns (uint256 currentStartId, uint256 count);
    }
}

/// Build the calldata for the multi-phase `claimCondition()` list-metadata
/// getter. Byte-identical to [`encode_claim_condition_single_phase`]'s
/// output (same selector, no arguments) -- reused directly rather than
/// duplicated, since the *calldata* is truly the same; only the
/// interpretation of the *response* differs by flavor.
pub fn encode_claim_condition_list() -> Bytes {
    encode_claim_condition_single_phase()
}

/// Decode the return data of the multi-phase `claimCondition()` getter as
/// `(currentStartId, count)`.
///
/// **Safety-critical decode order**: callers MUST attempt
/// [`decode_claim_condition_single_phase`] (the longer, ≥320-byte shape)
/// FIRST and only fall back to this function if that decode fails.
/// Verified empirically: `alloy_sol_types`'s ABI decoder does NOT reject
/// trailing bytes -- decoding a genuine single-phase `ClaimCondition`
/// response (which is always ≥320 bytes, even with empty `metadata`) as
/// this 64-byte 2-word shape SILENTLY SUCCEEDS, reading only the first
/// two words and discarding the rest, which would misidentify a
/// single-phase deployment as multi-phase with nonsensical
/// `currentStartId`/`count` values derived from unrelated fields
/// (`startTimestamp`/`maxClaimableSupply`). The reverse direction is
/// safe: decoding a genuine 64-byte multi-phase response as the ≥320-byte
/// single-phase shape correctly fails with a buffer-overrun error, since
/// there aren't enough bytes to satisfy it. This function must never be
/// called as the first/only decode attempt against calldata whose flavor
/// is not yet known.
pub fn decode_claim_condition_list(data: &[u8]) -> Result<(U256, U256), ThirdwebError> {
    let decoded = multi_phase_list::claimConditionCall::abi_decode_returns(data)
        .map_err(|e| ThirdwebError::AbiDecode(e.to_string()))?;
    Ok((decoded.currentStartId, decoded.count))
}

/// Build the calldata for `getSupplyClaimedByWallet(address)` -- the
/// single-phase ERC-721 flavor's one-argument overload. NEVER call this
/// against a multi-phase `Drop` contract expecting the two-argument
/// getter to be interchangeable -- the selectors are different and
/// `Drop.sol` has no single-argument overload of this function at all.
pub fn encode_get_supply_claimed_by_wallet_single_phase(claimer: Address) -> Bytes {
    Bytes::from(single_phase::getSupplyClaimedByWalletCall { claimer }.abi_encode())
}

/// Decode the return data of the single-phase `getSupplyClaimedByWallet(address)`.
pub fn decode_get_supply_claimed_by_wallet_single_phase(
    data: &[u8],
) -> Result<U256, ThirdwebError> {
    single_phase::getSupplyClaimedByWalletCall::abi_decode_returns(data)
        .map_err(|e| ThirdwebError::AbiDecode(e.to_string()))
}

/// Build the calldata for the ERC-721 `claim(...)` call.
pub fn encode_claim_721(
    receiver: Address,
    quantity: U256,
    currency: Address,
    price_per_token: U256,
    allowlist_proof: AllowlistProofAbi,
) -> Result<Bytes, ThirdwebError> {
    if receiver.is_zero() {
        return Err(ThirdwebError::ZeroNftContract);
    }
    Ok(Bytes::from(
        claimCall {
            receiver,
            quantity,
            currency,
            pricePerToken: price_per_token,
            allowlistProof: allowlist_proof,
            data: Bytes::new(),
        }
        .abi_encode(),
    ))
}

/// Build the calldata for the ERC-1155 `claim(...)` call (one extra
/// leading `tokenId`).
pub fn encode_claim_1155(
    receiver: Address,
    token_id: U256,
    quantity: U256,
    currency: Address,
    price_per_token: U256,
    allowlist_proof: AllowlistProofAbi,
) -> Result<Bytes, ThirdwebError> {
    if receiver.is_zero() {
        return Err(ThirdwebError::ZeroNftContract);
    }
    Ok(Bytes::from(
        claim1155Call {
            receiver,
            tokenId: token_id,
            quantity,
            currency,
            pricePerToken: price_per_token,
            allowlistProof: allowlist_proof,
            data: Bytes::new(),
        }
        .abi_encode(),
    ))
}

/// The allowlist leaf hash thirdweb's own `Drop.sol`/`DropSinglePhase.sol`
/// compute before verifying a proof against `merkleRoot`:
/// `keccak256(abi.encodePacked(claimer, quantityLimitPerWallet,
/// pricePerToken, currency))`. Tightly packed (`encodePacked`), not
/// padded (`encode`) -- `address` occupies exactly 20 bytes here, unlike
/// SeaDrop's allow-list leaf (`protocol::seadrop_crypto::allow_list_merkle_leaf`,
/// which uses padded `abi.encode` and is NOT interchangeable with this
/// one despite both being "an allow-list leaf hash").
pub fn allowlist_leaf(
    claimer: Address,
    quantity_limit_per_wallet: U256,
    price_per_token: U256,
    currency: Address,
) -> B256 {
    let mut buf = Vec::with_capacity(20 + 32 + 32 + 20);
    buf.extend_from_slice(claimer.as_slice());
    buf.extend_from_slice(&quantity_limit_per_wallet.to_be_bytes::<32>());
    buf.extend_from_slice(&price_per_token.to_be_bytes::<32>());
    buf.extend_from_slice(currency.as_slice());
    keccak256(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn sample_condition_abi() -> ClaimConditionAbi {
        ClaimConditionAbi {
            startTimestamp: U256::from(1_700_000_000u64),
            maxClaimableSupply: U256::from(1_000u64),
            supplyClaimed: U256::from(10u64),
            quantityLimitPerWallet: U256::from(5u64),
            merkleRoot: B256::ZERO,
            pricePerToken: U256::from(10_000_000_000_000_000u64),
            currency: NATIVE_TOKEN,
            metadata: String::new(),
        }
    }

    #[test]
    fn decode_claim_condition_round_trips() {
        let abi = sample_condition_abi();
        let encoded = getClaimConditionByIdCall::abi_encode_returns(&abi);
        let decoded = decode_get_claim_condition_by_id(&encoded).unwrap();
        assert_eq!(decoded.start_timestamp, 1_700_000_000);
        assert_eq!(decoded.max_claimable_supply, U256::from(1_000u64));
        assert_eq!(decoded.supply_claimed, U256::from(10u64));
        assert_eq!(decoded.quantity_limit_per_wallet, U256::from(5u64));
        assert_eq!(decoded.currency, NATIVE_TOKEN);
        assert!(decoded.is_native_currency());
    }

    #[test]
    fn decode_active_claim_condition_id_round_trips() {
        let encoded = getActiveClaimConditionIdCall::abi_encode_returns(&U256::from(3u64));
        let id = decode_get_active_claim_condition_id(&encoded).unwrap();
        assert_eq!(id, U256::from(3u64));
    }

    #[test]
    fn decode_supply_claimed_by_wallet_round_trips() {
        let encoded = getSupplyClaimedByWalletCall::abi_encode_returns(&U256::from(2u64));
        let claimed = decode_get_supply_claimed_by_wallet(&encoded).unwrap();
        assert_eq!(claimed, U256::from(2u64));
    }

    #[test]
    fn encode_get_supply_claimed_by_wallet_is_keyed_by_condition_id_and_claimer() {
        let claimer = address!("5555555555555555555555555555555555555555");
        let a = encode_get_supply_claimed_by_wallet(U256::from(0u64), claimer);
        let b = encode_get_supply_claimed_by_wallet(U256::from(1u64), claimer);
        assert_ne!(
            a, b,
            "the same wallet's claimed count must be looked up per claim-condition id, not a \
             single lifetime-cumulative counter"
        );
    }

    #[test]
    fn claim_condition_single_phase_selector_differs_from_get_claim_condition_by_id() {
        // The single-phase getter (claimCondition(), no args) and the
        // multi-phase getter (getClaimConditionById(uint256)) are
        // different on-chain functions with different selectors -- if
        // these ever collided, calling one against the wrong flavor's
        // contract could silently decode successfully against an
        // unrelated function's return data.
        assert_ne!(
            claimConditionCall::SELECTOR,
            getClaimConditionByIdCall::SELECTOR
        );
    }

    #[test]
    fn get_supply_claimed_by_wallet_single_phase_selector_differs_from_multi_phase() {
        // The critical regression this correction exists for: an earlier
        // version of this module assumed the single-phase flavor's
        // getSupplyClaimedByWallet(address) shared a selector with (or
        // could be called via) the multi-phase
        // getSupplyClaimedByWallet(uint256,address) overload. Solidity
        // computes selectors from the full signature including argument
        // types, so these are genuinely different 4-byte values, and
        // calling the wrong one against a real single-phase deployment
        // would target a nonexistent function.
        assert_ne!(
            single_phase::getSupplyClaimedByWalletCall::SELECTOR,
            getSupplyClaimedByWalletCall::SELECTOR
        );
    }

    #[test]
    fn decode_claim_condition_single_phase_round_trips() {
        let abi = sample_condition_abi();
        let encoded = claimConditionCall::abi_encode_returns(&abi);
        let decoded = decode_claim_condition_single_phase(&encoded).unwrap();
        assert_eq!(decoded.start_timestamp, 1_700_000_000);
        assert_eq!(
            decoded.price_per_token,
            U256::from(10_000_000_000_000_000u64)
        );
    }

    #[test]
    fn decode_supply_claimed_by_wallet_single_phase_round_trips() {
        let encoded =
            single_phase::getSupplyClaimedByWalletCall::abi_encode_returns(&U256::from(4u64));
        let claimed = decode_get_supply_claimed_by_wallet_single_phase(&encoded).unwrap();
        assert_eq!(claimed, U256::from(4u64));
    }

    #[test]
    fn encode_claim_condition_single_phase_has_no_arguments() {
        // A no-argument call is exactly 4 bytes (the selector alone).
        let calldata = encode_claim_condition_single_phase();
        assert_eq!(calldata.len(), 4);
        assert_eq!(&calldata[..], claimConditionCall::SELECTOR.as_slice());
    }

    #[test]
    fn zero_max_claimable_supply_means_literally_zero_remaining_never_unlimited() {
        // Verified directly against Drop.sol's verifyClaim: there is no
        // "0 means unlimited" special case in the real contract.
        let mut abi = sample_condition_abi();
        abi.maxClaimableSupply = U256::ZERO;
        abi.supplyClaimed = U256::ZERO;
        let condition = ClaimCondition::from_abi(abi).unwrap();
        assert_eq!(condition.supply_remaining(), U256::ZERO);
    }

    #[test]
    fn exhausted_supply_reports_zero_remaining() {
        let mut abi = sample_condition_abi();
        abi.maxClaimableSupply = U256::from(10u64);
        abi.supplyClaimed = U256::from(10u64);
        let condition = ClaimCondition::from_abi(abi).unwrap();
        assert_eq!(condition.supply_remaining(), U256::ZERO);
    }

    #[test]
    fn erc20_currency_is_not_reported_as_native() {
        let mut abi = sample_condition_abi();
        abi.currency = address!("00000000000000000000000000000000000dEaD0");
        let condition = ClaimCondition::from_abi(abi).unwrap();
        assert!(!condition.is_native_currency());
    }

    #[test]
    fn encode_claim_721_zero_receiver_is_rejected() {
        let err = encode_claim_721(
            Address::ZERO,
            U256::from(1u64),
            NATIVE_TOKEN,
            U256::ZERO,
            AllowlistProofAbi {
                proof: vec![],
                quantityLimitPerWallet: U256::ZERO,
                pricePerToken: U256::ZERO,
                currency: NATIVE_TOKEN,
            },
        )
        .unwrap_err();
        assert_eq!(err, ThirdwebError::ZeroNftContract);
    }

    #[test]
    fn encode_claim_721_selector_matches_the_real_claim_function() {
        let calldata = encode_claim_721(
            address!("1111111111111111111111111111111111111111"),
            U256::from(2u64),
            NATIVE_TOKEN,
            U256::from(1u64),
            AllowlistProofAbi {
                proof: vec![],
                quantityLimitPerWallet: U256::ZERO,
                pricePerToken: U256::ZERO,
                currency: NATIVE_TOKEN,
            },
        )
        .unwrap();
        assert!(calldata.starts_with(&claimCall::SELECTOR));
    }

    #[test]
    fn encode_claim_1155_selector_differs_from_the_721_variant() {
        let common_proof = AllowlistProofAbi {
            proof: vec![],
            quantityLimitPerWallet: U256::ZERO,
            pricePerToken: U256::ZERO,
            currency: NATIVE_TOKEN,
        };
        let calldata_721 = encode_claim_721(
            address!("1111111111111111111111111111111111111111"),
            U256::from(1u64),
            NATIVE_TOKEN,
            U256::ZERO,
            common_proof.clone(),
        )
        .unwrap();
        let calldata_1155 = encode_claim_1155(
            address!("1111111111111111111111111111111111111111"),
            U256::from(7u64),
            U256::from(1u64),
            NATIVE_TOKEN,
            U256::ZERO,
            common_proof,
        )
        .unwrap();
        assert_ne!(&calldata_721[0..4], &calldata_1155[0..4]);
    }

    /// Independently reconstructs thirdweb's own documented leaf-hash
    /// computation (`keccak256(abi.encodePacked(claimer,
    /// quantityLimitPerWallet, pricePerToken, currency))`) byte-for-byte,
    /// as a regression guard distinct from the implementation under test.
    #[test]
    fn allowlist_leaf_matches_manual_packed_encoding() {
        let claimer = address!("2222222222222222222222222222222222222222");
        let quantity_limit = U256::from(3u64);
        let price = U256::from(5_000_000_000_000_000u64);
        let currency = NATIVE_TOKEN;

        let mut expected = Vec::new();
        expected.extend_from_slice(claimer.as_slice());
        expected.extend_from_slice(&quantity_limit.to_be_bytes::<32>());
        expected.extend_from_slice(&price.to_be_bytes::<32>());
        expected.extend_from_slice(currency.as_slice());
        let expected_leaf = keccak256(expected);

        assert_eq!(
            allowlist_leaf(claimer, quantity_limit, price, currency),
            expected_leaf
        );
    }

    #[test]
    fn allowlist_leaf_changes_with_claimer() {
        let a = allowlist_leaf(
            address!("1111111111111111111111111111111111111111"),
            U256::ZERO,
            U256::ZERO,
            NATIVE_TOKEN,
        );
        let b = allowlist_leaf(
            address!("2222222222222222222222222222222222222222"),
            U256::ZERO,
            U256::ZERO,
            NATIVE_TOKEN,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn allowlist_leaf_changes_with_quantity_limit() {
        let claimer = address!("1111111111111111111111111111111111111111");
        let a = allowlist_leaf(claimer, U256::from(1u64), U256::ZERO, NATIVE_TOKEN);
        let b = allowlist_leaf(claimer, U256::from(2u64), U256::ZERO, NATIVE_TOKEN);
        assert_ne!(a, b);
    }

    #[test]
    fn allowlist_leaf_changes_with_price() {
        let claimer = address!("1111111111111111111111111111111111111111");
        let a = allowlist_leaf(claimer, U256::ZERO, U256::from(1u64), NATIVE_TOKEN);
        let b = allowlist_leaf(claimer, U256::ZERO, U256::from(2u64), NATIVE_TOKEN);
        assert_ne!(a, b);
    }

    #[test]
    fn allowlist_leaf_changes_with_currency() {
        let claimer = address!("1111111111111111111111111111111111111111");
        let other_currency = address!("3333333333333333333333333333333333333333");
        let a = allowlist_leaf(claimer, U256::ZERO, U256::ZERO, NATIVE_TOKEN);
        let b = allowlist_leaf(claimer, U256::ZERO, U256::ZERO, other_currency);
        assert_ne!(a, b);
    }

    /// A single-leaf tree (leaf == root, empty proof) is the simplest
    /// genuine verification -- proves `allowlist_leaf` composes correctly
    /// with the already-hardened, protocol-agnostic
    /// `seadrop_crypto::verify_merkle_proof` (sorted-pair
    /// `commutativeKeccak256`, identical to OpenZeppelin's `MerkleProof.verify`
    /// thirdweb itself uses -- only the leaf encoding differs by protocol).
    #[test]
    fn allowlist_leaf_verifies_against_a_single_leaf_tree_root() {
        let claimer = address!("4444444444444444444444444444444444444444");
        let leaf = allowlist_leaf(claimer, U256::from(1u64), U256::ZERO, NATIVE_TOKEN);
        assert!(crate::protocol::seadrop_crypto::verify_merkle_proof(
            &[],
            leaf,
            leaf
        ));
    }
}
