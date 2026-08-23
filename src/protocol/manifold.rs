//! Independent local encoding/decoding of Manifold's `LazyPayableClaim`
//! extension ABI, verified directly against the official
//! `manifoldxyz/creator-core-extensions-solidity` source (not a
//! search-result summary):
//! `packages/manifold/contracts/lazyclaim/IERC721LazyPayableClaim.sol`,
//! `ILazyPayableClaim.sol`, `ILazyPayableClaimCore.sol`,
//! `LazyPayableClaimCore.sol`, `LazyPayableClaim.sol`.
//!
//! **Architecture is genuinely different from thirdweb's Drop**: a
//! Manifold claim is not the NFT contract itself. Minting goes through a
//! separate, shared *extension* contract (`ERC721LazyPayableClaim`,
//! typically one canonical deployment per chain, registered as an
//! extension on many different creator (NFT) contracts) that the creator
//! contract has approved to mint on its behalf. A specific claim is
//! addressed by `(creatorContractAddress, instanceId)` on that extension
//! contract -- both are required, and neither alone identifies a claim.
//! Kairox therefore needs the extension contract's address (the `eth_call`/
//! `eth_sendTransaction` target) *and* the creator contract address *and*
//! the instance id, not just one collection address.
//!
//! **Extension auto-discovery is possible; instance auto-discovery is
//! not.** The creator contract (`ICreatorCore.sol`, verified against
//! `manifoldxyz/creator-core-solidity`) exposes `getExtensions() external
//! view returns (address[] memory)` -- a real, bounded, on-chain
//! enumeration of every extension ever registered against it (see
//! [`encode_get_extensions`]/[`decode_get_extensions`]), which lets
//! `execution::manifold_engine`/`cli::commands::resolver_adapters::ManifoldAdapter`
//! auto-fill `--manifold-extension` when exactly one candidate is found.
//! No equivalent exists for `instanceId`: `LazyPayableClaimCore.sol`
//! keeps no counter or list of instance ids for a given creator contract
//! anywhere in its state -- `getClaim(creator, instanceId)` requires the
//! id already known. This was verified by reading the full deployed
//! source, not assumed. `--instance-id` therefore remains a required,
//! always-explicit operator input; Manifold support is honestly
//! **partial auto-discovery**, never "fully automatic".
//!
//! **Scope of this module (v0.8, first Manifold pass)**: the V1
//! `ERC721LazyPayableClaim` extension only -- single-token `mint()` (not
//! `mintBatch`/`mintProxy`/`mintSignature`), native-currency claims only.
//! Deliberately deferred, not silently assumed compatible:
//! - `mintBatch`/quantity > 1 in one call (requires per-index
//!   `mintIndices`/`merkleProofs` arrays whose required shape for a
//!   *public*, non-merkle claim was not confirmed against source this
//!   pass).
//! - ERC-1155 claims (`ERC1155LazyPayableClaim`) -- a structurally
//!   different extension contract.
//! - The V2 "updatable fee" extension family
//!   (`packages/manifold/contracts/lazyUpdatableFeeClaim/*`) -- V1's
//!   `MINT_FEE`/`MINT_FEE_MERKLE` are fixed `public constant`s; V2 makes
//!   the fee mutable via a different mechanism this module does not read.
//!   Mixing up V1/V2 fee semantics would either revert (safe, if Kairox
//!   underestimates required `msg.value`) or silently overpay (if it
//!   overestimates) -- treated as a distinct, unverified flavor rather
//!   than assumed identical to V1.
//! - ERC-20-denominated claims (`Claim.erc20 != 0`).
//! - Delegated minting (`mintFor != sender`, via Manifold's
//!   delegation-registry integration) -- Kairox always mints for the
//!   wallet whose key it holds, so the merkle leaf is always
//!   `keccak256(abi.encodePacked(wallet, mintIndex))`.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, sol};
use thiserror::Error;

/// `Claim.cost`/`msg.value` protocol fee for a non-merkle (public) claim,
/// in wei -- `LazyPayableClaim.sol`'s `MINT_FEE` `public constant`.
/// V1-extension-specific; see this module's doc comment on why V2 is out
/// of scope.
pub const MINT_FEE_WEI: U256 = U256::from_limbs([500_000_000_000_000, 0, 0, 0]);

/// `Claim.cost`/`msg.value` protocol fee for a merkle-gated claim, in wei
/// -- `LazyPayableClaim.sol`'s `MINT_FEE_MERKLE` `public constant`.
pub const MINT_FEE_MERKLE_WEI: U256 = U256::from_limbs([690_000_000_000_000, 0, 0, 0]);

sol! {
    #[derive(Debug)]
    // Verified against IERC721LazyPayableClaim.sol's `Claim` struct --
    // field order matters, it is exactly the external `getClaim` return
    // tuple's shape.
    struct ClaimAbi {
        uint32 total;
        uint32 totalMax;
        uint32 walletMax;
        // Declared as uint256 rather than the real contract's uint48:
        // Solidity's ABI encoding pads every elementary static type to a
        // full 32-byte word regardless of declared bit width, so the
        // on-the-wire bytes are identical either way -- this avoids an
        // awkward alloy_primitives::Uint<48, 1> <-> u64 conversion for a
        // value that will never exceed 48 bits in practice.
        uint256 startDate;
        uint256 endDate;
        uint8 storageProtocol;
        uint8 contractVersion;
        bool identical;
        bytes32 merkleRoot;
        string location;
        uint256 cost;
        address paymentReceiver;
        address erc20;
        address signingAddress;
    }

    function getClaim(address creatorContractAddress, uint256 instanceId) external view returns (ClaimAbi memory);

    function getTotalMints(address minter, address creatorContractAddress, uint256 instanceId)
        external
        view
        returns (uint32);

    // `address public MEMBERSHIP_ADDRESS;` -- Solidity's auto-generated
    // getter for a public state variable has the exact same name.
    function MEMBERSHIP_ADDRESS() external view returns (address);

    function isActiveMember(address sender) external view returns (bool);

    // `ICreatorCore.sol`'s extension enumeration -- note this targets the
    // CREATOR contract, not the LazyPayableClaim extension contract (a
    // genuinely different ABI/address, verified separately). Real,
    // bounded, on-chain: every creator contract (ERC721Creator/
    // ERC1155Creator) implements this.
    function getExtensions() external view returns (address[] memory);

    // ILazyPayableClaim.sol's `mint` -- verified verbatim, including
    // parameter order and names.
    function mint(
        address creatorContractAddress,
        uint256 instanceId,
        uint32 mintIndex,
        bytes32[] calldata merkleProof,
        address mintFor
    ) external payable;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifoldError {
    #[error("creator contract address must not be the zero address")]
    ZeroCreatorContract,
    #[error("startDate/endDate does not fit safely in a u64 conversion")]
    TimestampOverflow,
    #[error("failed to decode ABI return data: {0}")]
    AbiDecode(String),
    #[error(
        "claim pays in ERC-20 currency {0:#x}, not the native token; ERC20-priced Manifold \
         claims are not yet supported"
    )]
    Erc20CurrencyUnsupported(Address),
}

/// Normalized, validated `Claim` state for one `(creatorContractAddress,
/// instanceId)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifoldClaim {
    pub total: u32,
    pub total_max: u32,
    pub wallet_max: u32,
    pub start_date: u64,
    pub end_date: u64,
    pub merkle_root: B256,
    pub cost: U256,
    pub payment_receiver: Address,
    pub erc20: Address,
}

impl ManifoldClaim {
    fn from_abi(abi: ClaimAbi) -> Result<Self, ManifoldError> {
        Ok(Self {
            total: abi.total,
            total_max: abi.totalMax,
            wallet_max: abi.walletMax,
            start_date: abi
                .startDate
                .try_into()
                .map_err(|_| ManifoldError::TimestampOverflow)?,
            end_date: abi
                .endDate
                .try_into()
                .map_err(|_| ManifoldError::TimestampOverflow)?,
            merkle_root: abi.merkleRoot,
            cost: abi.cost,
            payment_receiver: abi.paymentReceiver,
            erc20: abi.erc20,
        })
    }

    /// `true` only when this claim is paid in the chain's native
    /// currency -- Manifold represents that as `erc20 == address(0)`
    /// (verified against `Claim.erc20`'s use in `_transferFunds`), unlike
    /// thirdweb's `0xeeee...` sentinel. Never inferred from anything but
    /// this exact field.
    pub fn is_native_currency(&self) -> bool {
        self.erc20.is_zero()
    }

    /// `totalMax - total`, saturating -- `totalMax == 0` is Manifold's own
    /// documented "no cap" convention for this field (unlike thirdweb's
    /// `maxClaimableSupply`, which has no such special case -- verified
    /// separately per-protocol, never assumed to generalize). Represented
    /// here as `u32::MAX` remaining when `totalMax == 0`, since Manifold
    /// itself treats an uncapped claim as unbounded.
    pub fn supply_remaining(&self) -> u32 {
        if self.total_max == 0 {
            u32::MAX
        } else {
            self.total_max.saturating_sub(self.total)
        }
    }

    /// Whether this claim requires a merkle allowlist proof to mint.
    pub fn is_gated(&self) -> bool {
        self.merkle_root != B256::ZERO
    }

    /// A stable fingerprint of this claim's execution-affecting
    /// configuration -- `total_max`, `wallet_max`, `start_date`,
    /// `end_date`, `merkle_root`, `cost`, `payment_receiver`, `erc20`.
    /// Deliberately EXCLUDES `total` (the mint counter, which increments
    /// with every claim and is never grounds for treating a watched
    /// claim as changed). Manifold's own `updateClaim(creatorContractAddress,
    /// instanceId, claimParameters)` (verified against
    /// `IERC721LazyPayableClaim.sol`) can rewrite a claim's terms in
    /// place while its `instanceId` stays the same, so the three native
    /// identifiers alone do not prove unchanged semantics -- a `watch`
    /// attempt must be able to detect a fingerprint change and stop.
    pub fn config_fingerprint(&self) -> B256 {
        let mut buf = Vec::with_capacity(4 + 4 + 8 + 8 + 32 + 32 + 20 + 20);
        buf.extend_from_slice(&self.total_max.to_be_bytes());
        buf.extend_from_slice(&self.wallet_max.to_be_bytes());
        buf.extend_from_slice(&self.start_date.to_be_bytes());
        buf.extend_from_slice(&self.end_date.to_be_bytes());
        buf.extend_from_slice(self.merkle_root.as_slice());
        buf.extend_from_slice(&self.cost.to_be_bytes::<32>());
        buf.extend_from_slice(self.payment_receiver.as_slice());
        buf.extend_from_slice(self.erc20.as_slice());
        keccak256(buf)
    }
}

/// Build the calldata for `getClaim(creatorContractAddress, instanceId)`.
pub fn encode_get_claim(
    creator_contract: Address,
    instance_id: U256,
) -> Result<Bytes, ManifoldError> {
    if creator_contract.is_zero() {
        return Err(ManifoldError::ZeroCreatorContract);
    }
    Ok(Bytes::from(
        getClaimCall {
            creatorContractAddress: creator_contract,
            instanceId: instance_id,
        }
        .abi_encode(),
    ))
}

/// Decode the return data of `getClaim(...)`.
pub fn decode_get_claim(data: &[u8]) -> Result<ManifoldClaim, ManifoldError> {
    let decoded = getClaimCall::abi_decode_returns(data)
        .map_err(|e| ManifoldError::AbiDecode(e.to_string()))?;
    ManifoldClaim::from_abi(decoded)
}

/// Build the calldata for `getExtensions()` on a Manifold creator
/// (`ICreatorCore`) contract -- verified against
/// `manifoldxyz/creator-core-solidity`'s `ICreatorCore.sol`. Targets the
/// creator contract, never the `LazyPayableClaim` extension contract.
pub fn encode_get_extensions() -> Bytes {
    Bytes::from(getExtensionsCall {}.abi_encode())
}

/// Decode the return data of `getExtensions()`.
pub fn decode_get_extensions(data: &[u8]) -> Result<Vec<Address>, ManifoldError> {
    getExtensionsCall::abi_decode_returns(data).map_err(|e| ManifoldError::AbiDecode(e.to_string()))
}

/// Build the calldata for `getTotalMints(minter, creatorContractAddress, instanceId)`.
pub fn encode_get_total_mints(
    minter: Address,
    creator_contract: Address,
    instance_id: U256,
) -> Bytes {
    Bytes::from(
        getTotalMintsCall {
            minter,
            creatorContractAddress: creator_contract,
            instanceId: instance_id,
        }
        .abi_encode(),
    )
}

/// Decode the return data of `getTotalMints(...)`.
pub fn decode_get_total_mints(data: &[u8]) -> Result<u32, ManifoldError> {
    getTotalMintsCall::abi_decode_returns(data).map_err(|e| ManifoldError::AbiDecode(e.to_string()))
}

/// Build the calldata for `MEMBERSHIP_ADDRESS()`.
pub fn encode_membership_address() -> Bytes {
    Bytes::from(MEMBERSHIP_ADDRESSCall {}.abi_encode())
}

/// Decode the return data of `MEMBERSHIP_ADDRESS()`.
pub fn decode_membership_address(data: &[u8]) -> Result<Address, ManifoldError> {
    MEMBERSHIP_ADDRESSCall::abi_decode_returns(data)
        .map_err(|e| ManifoldError::AbiDecode(e.to_string()))
}

/// Build the calldata for `isActiveMember(address)` against the Manifold
/// Membership contract (a different address from the extension contract
/// -- read [`decode_membership_address`]'s result first).
pub fn encode_is_active_member(sender: Address) -> Bytes {
    Bytes::from(isActiveMemberCall { sender }.abi_encode())
}

/// Decode the return data of `isActiveMember(address)`.
pub fn decode_is_active_member(data: &[u8]) -> Result<bool, ManifoldError> {
    isActiveMemberCall::abi_decode_returns(data)
        .map_err(|e| ManifoldError::AbiDecode(e.to_string()))
}

/// Build the calldata for the single-token `mint(...)` call. `mint_index`/
/// `merkle_proof` are only consulted on-chain when the claim is
/// merkle-gated -- verified against `LazyPayableClaimCore.sol`'s
/// `_checkMerkleAndUpdate`/non-merkle branch split; pass `0`/`&[]` for a
/// public (non-gated) claim.
pub fn encode_mint(
    creator_contract: Address,
    instance_id: U256,
    mint_index: u32,
    merkle_proof: &[B256],
    mint_for: Address,
) -> Result<Bytes, ManifoldError> {
    if creator_contract.is_zero() {
        return Err(ManifoldError::ZeroCreatorContract);
    }
    Ok(Bytes::from(
        mintCall {
            creatorContractAddress: creator_contract,
            instanceId: instance_id,
            mintIndex: mint_index,
            merkleProof: merkle_proof.to_vec(),
            mintFor: mint_for,
        }
        .abi_encode(),
    ))
}

/// The merkle allowlist leaf Manifold's own
/// `LazyPayableClaimCore.sol::_checkMerkleAndUpdate` computes before
/// verifying a proof against `Claim.merkleRoot`:
/// `keccak256(abi.encodePacked(mintFor, mintIndex))` -- tightly packed
/// (`address` 20 bytes + `uint32` 4 bytes, big-endian, 24 bytes total).
/// Genuinely different from both thirdweb's and SeaDrop's allow-list leaf
/// formulas -- verified independently against Manifold's own source, never
/// assumed to match either.
pub fn allowlist_leaf(mint_for: Address, mint_index: u32) -> B256 {
    let mut buf = Vec::with_capacity(20 + 4);
    buf.extend_from_slice(mint_for.as_slice());
    buf.extend_from_slice(&mint_index.to_be_bytes());
    keccak256(buf)
}

/// The `msg.value` a single `mint()` call must send, verified against
/// `LazyPayableClaim.sol::_transferFunds`'s `require(msg.value >=
/// payableCost, ...)`: the claim's own `cost`, plus [`MINT_FEE_WEI`] (or
/// [`MINT_FEE_MERKLE_WEI`] for a gated claim) unless the wallet holds an
/// active Manifold Membership (`membership_address` zero, or
/// `is_active_member` false, both make the fee apply). `>=`, not `==`, so
/// this exact value is always sufficient -- Kairox never underpays and
/// never needs to guess at a refund.
pub fn required_msg_value(
    claim: &ManifoldClaim,
    membership_address: Address,
    is_active_member: bool,
) -> U256 {
    let fee_exempt = !membership_address.is_zero() && is_active_member;
    if fee_exempt {
        claim.cost
    } else if claim.is_gated() {
        claim.cost.saturating_add(MINT_FEE_MERKLE_WEI)
    } else {
        claim.cost.saturating_add(MINT_FEE_WEI)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use alloy_sol_types::SolValue;

    fn sample_claim_abi() -> ClaimAbi {
        ClaimAbi {
            total: 3,
            totalMax: 100,
            walletMax: 2,
            startDate: U256::from(1_700_000_000u64),
            endDate: U256::from(1_800_000_000u64),
            storageProtocol: 3,
            contractVersion: 1,
            identical: true,
            merkleRoot: B256::ZERO,
            location: "ipfs://abc".to_string(),
            cost: U256::from(1_000_000_000_000_000u64),
            paymentReceiver: address!("1111111111111111111111111111111111111111"),
            erc20: Address::ZERO,
            signingAddress: Address::ZERO,
        }
    }

    #[test]
    fn decode_get_claim_round_trips() {
        let abi = sample_claim_abi();
        let encoded = abi.clone().abi_encode();
        let decoded = decode_get_claim(&encoded).unwrap();
        assert_eq!(decoded.total, 3);
        assert_eq!(decoded.total_max, 100);
        assert_eq!(decoded.wallet_max, 2);
        assert_eq!(decoded.start_date, 1_700_000_000);
        assert_eq!(decoded.end_date, 1_800_000_000);
        assert_eq!(decoded.cost, U256::from(1_000_000_000_000_000u64));
        assert!(decoded.is_native_currency());
        assert!(!decoded.is_gated());
    }

    #[test]
    fn zero_total_max_means_unbounded_remaining_supply() {
        let mut abi = sample_claim_abi();
        abi.totalMax = 0;
        let claim = ManifoldClaim::from_abi(abi).unwrap();
        assert_eq!(claim.supply_remaining(), u32::MAX);
    }

    #[test]
    fn nonzero_total_max_computes_remaining_supply() {
        let claim = ManifoldClaim::from_abi(sample_claim_abi()).unwrap();
        assert_eq!(claim.supply_remaining(), 97);
    }

    #[test]
    fn nonzero_merkle_root_is_gated() {
        let mut abi = sample_claim_abi();
        abi.merkleRoot = B256::from([0x11; 32]);
        let claim = ManifoldClaim::from_abi(abi).unwrap();
        assert!(claim.is_gated());
    }

    #[test]
    fn nonzero_erc20_is_not_native_currency() {
        let mut abi = sample_claim_abi();
        abi.erc20 = address!("2222222222222222222222222222222222222222");
        let claim = ManifoldClaim::from_abi(abi).unwrap();
        assert!(!claim.is_native_currency());
    }

    #[test]
    fn encode_get_claim_rejects_zero_creator_contract() {
        assert_eq!(
            encode_get_claim(Address::ZERO, U256::from(1)).unwrap_err(),
            ManifoldError::ZeroCreatorContract
        );
    }

    #[test]
    fn encode_mint_rejects_zero_creator_contract() {
        assert_eq!(
            encode_mint(Address::ZERO, U256::from(1), 0, &[], Address::ZERO).unwrap_err(),
            ManifoldError::ZeroCreatorContract
        );
    }

    #[test]
    fn encode_mint_selector_matches_the_real_mint_function() {
        let calldata = encode_mint(
            address!("3333333333333333333333333333333333333333"),
            U256::from(7),
            0,
            &[],
            address!("4444444444444444444444444444444444444444"),
        )
        .unwrap();
        assert_eq!(&calldata[0..4], mintCall::SELECTOR);
    }

    #[test]
    fn allowlist_leaf_matches_manual_packed_encoding() {
        let claimer = address!("5555555555555555555555555555555555555555");
        let mint_index: u32 = 42;
        let mut manual = Vec::new();
        manual.extend_from_slice(claimer.as_slice());
        manual.extend_from_slice(&mint_index.to_be_bytes());
        assert_eq!(allowlist_leaf(claimer, mint_index), keccak256(manual));
    }

    #[test]
    fn allowlist_leaf_changes_with_mint_index() {
        let claimer = address!("6666666666666666666666666666666666666666");
        assert_ne!(allowlist_leaf(claimer, 1), allowlist_leaf(claimer, 2));
    }

    #[test]
    fn allowlist_leaf_changes_with_claimer() {
        let a = address!("7777777777777777777777777777777777777777");
        let b = address!("8888888888888888888888888888888888888888");
        assert_ne!(allowlist_leaf(a, 5), allowlist_leaf(b, 5));
    }

    #[test]
    fn allowlist_leaf_verifies_against_a_single_leaf_tree_root() {
        use crate::protocol::seadrop_crypto::verify_merkle_proof;
        let claimer = address!("9999999999999999999999999999999999999999");
        let leaf = allowlist_leaf(claimer, 3);
        assert!(verify_merkle_proof(&[], leaf, leaf));
    }

    #[test]
    fn required_value_for_ungated_non_member_is_cost_plus_mint_fee() {
        let claim = ManifoldClaim::from_abi(sample_claim_abi()).unwrap();
        let value = required_msg_value(&claim, Address::ZERO, false);
        assert_eq!(value, claim.cost + MINT_FEE_WEI);
    }

    #[test]
    fn required_value_for_gated_non_member_is_cost_plus_merkle_mint_fee() {
        let mut abi = sample_claim_abi();
        abi.merkleRoot = B256::from([0x22; 32]);
        let claim = ManifoldClaim::from_abi(abi).unwrap();
        let value = required_msg_value(&claim, Address::ZERO, false);
        assert_eq!(value, claim.cost + MINT_FEE_MERKLE_WEI);
    }

    #[test]
    fn required_value_for_active_member_omits_the_fee() {
        let claim = ManifoldClaim::from_abi(sample_claim_abi()).unwrap();
        let membership = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let value = required_msg_value(&claim, membership, true);
        assert_eq!(value, claim.cost);
    }

    #[test]
    fn required_value_when_membership_configured_but_not_active_still_includes_fee() {
        let claim = ManifoldClaim::from_abi(sample_claim_abi()).unwrap();
        let membership = address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let value = required_msg_value(&claim, membership, false);
        assert_eq!(value, claim.cost + MINT_FEE_WEI);
    }

    #[test]
    fn getclaim_selector_matches_the_real_function() {
        let calldata = encode_get_claim(
            address!("cccccccccccccccccccccccccccccccccccccccc"),
            U256::from(1),
        )
        .unwrap();
        assert_eq!(&calldata[0..4], getClaimCall::SELECTOR);
    }

    #[test]
    fn get_extensions_selector_matches_the_real_function() {
        let calldata = encode_get_extensions();
        assert_eq!(&calldata[0..4], getExtensionsCall::SELECTOR);
    }

    #[test]
    fn get_extensions_takes_no_arguments() {
        assert_eq!(encode_get_extensions().len(), 4);
    }

    #[test]
    fn decode_get_extensions_round_trips_an_empty_list() {
        let encoded = getExtensionsCall::abi_encode_returns(&vec![]);
        assert_eq!(
            decode_get_extensions(&encoded).unwrap(),
            Vec::<Address>::new()
        );
    }

    #[test]
    fn decode_get_extensions_round_trips_multiple_addresses() {
        let a = address!("1234567890123456789012345678901234567890");
        let b = address!("0987654321098765432109876543210987654321");
        let encoded = getExtensionsCall::abi_encode_returns(&vec![a, b]);
        assert_eq!(decode_get_extensions(&encoded).unwrap(), vec![a, b]);
    }
}
