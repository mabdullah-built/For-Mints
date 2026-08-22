//! Thin wrappers that fetch and decode the specific on-chain reads Kairox
//! needs, using the local, independent SeaDrop ABI encoders in
//! [`crate::protocol::seadrop`] — never any third-party API.

use alloy_primitives::{Address, Bytes, U256};

use crate::chain::rpc::{BlockHeader, RpcClient};
use crate::execution::errors::{KairoxError, SessionError};
use crate::protocol::seadrop::{self, MintStats, PublicDropConfig};
use crate::protocol::thirdweb::{self, ClaimCondition};

/// Conservative fallback gas limit used only when `eth_estimateGas` cannot
/// be completed (e.g. the stage has not opened yet, so a live mint call
/// would revert). Safety caps still apply on top of this value.
pub const FALLBACK_GAS_LIMIT: u64 = 250_000;

/// Conservative fallback priority fee (1.5 gwei) used only when
/// `eth_maxPriorityFeePerGas` is unavailable.
pub const FALLBACK_PRIORITY_FEE_WEI: u128 = 1_500_000_000;

pub async fn fetch_public_drop(
    client: &RpcClient,
    seadrop_contract: Address,
    nft_contract: Address,
) -> Result<PublicDropConfig, KairoxError> {
    let calldata = seadrop::encode_get_public_drop(nft_contract)?;
    let result = client.eth_call(seadrop_contract, &calldata).await?;
    Ok(seadrop::decode_get_public_drop(&result)?)
}

pub async fn fetch_allowed_fee_recipients(
    client: &RpcClient,
    seadrop_contract: Address,
    nft_contract: Address,
) -> Result<Vec<Address>, KairoxError> {
    let calldata = seadrop::encode_get_allowed_fee_recipients(nft_contract)?;
    let result = client.eth_call(seadrop_contract, &calldata).await?;
    Ok(seadrop::decode_get_allowed_fee_recipients(&result)?)
}

/// Fetch `getMintStats(minter)` from the NFT token contract. This is the
/// one source of both per-wallet `alreadyMinted` and collection supply —
/// Kairox has no other source for either, so a failure here propagates and
/// the caller fails closed rather than guessing.
pub async fn fetch_mint_stats(
    client: &RpcClient,
    nft_contract: Address,
    minter: Address,
) -> Result<MintStats, KairoxError> {
    let calldata = seadrop::encode_get_mint_stats(minter);
    let result = client.eth_call(nft_contract, &calldata).await?;
    Ok(seadrop::decode_get_mint_stats(&result)?)
}

/// Fetch `getActiveClaimConditionId()` from a thirdweb Drop contract
/// (which is the NFT contract itself -- thirdweb Drop contracts implement
/// the NFT and its claim logic in one deployment, unlike SeaDrop's
/// separate protocol-singleton/collection split).
pub async fn fetch_thirdweb_active_claim_condition_id(
    client: &RpcClient,
    drop_contract: Address,
) -> Result<U256, KairoxError> {
    let calldata = thirdweb::encode_get_active_claim_condition_id();
    let result = client.eth_call(drop_contract, &calldata).await?;
    Ok(thirdweb::decode_get_active_claim_condition_id(&result)?)
}

/// Fetch `getClaimConditionById(conditionId)` from a thirdweb Drop
/// contract.
pub async fn fetch_thirdweb_claim_condition_by_id(
    client: &RpcClient,
    drop_contract: Address,
    condition_id: U256,
) -> Result<ClaimCondition, KairoxError> {
    let calldata = thirdweb::encode_get_claim_condition_by_id(condition_id);
    let result = client.eth_call(drop_contract, &calldata).await?;
    Ok(thirdweb::decode_get_claim_condition_by_id(&result)?)
}

/// Fetch `getSupplyClaimedByWallet(conditionId, claimer)` from a thirdweb
/// Drop contract -- the counter is keyed per claim-condition id (see
/// `protocol::thirdweb::encode_get_supply_claimed_by_wallet`'s doc
/// comment), so `condition_id` must be the *current* active condition id
/// for this to mean "how much has this wallet already claimed in the
/// phase it is about to claim in".
pub async fn fetch_thirdweb_supply_claimed_by_wallet(
    client: &RpcClient,
    drop_contract: Address,
    condition_id: U256,
    claimer: Address,
) -> Result<U256, KairoxError> {
    let calldata = thirdweb::encode_get_supply_claimed_by_wallet(condition_id, claimer);
    let result = client.eth_call(drop_contract, &calldata).await?;
    Ok(thirdweb::decode_get_supply_claimed_by_wallet(&result)?)
}

/// Base fee plus block context, and (best-effort) a suggested priority fee.
pub struct FeeHint {
    pub base_fee_per_gas: u128,
    pub suggested_priority_fee: Option<u128>,
    pub block: BlockHeader,
}

pub async fn fetch_fee_hint(client: &RpcClient) -> Result<FeeHint, KairoxError> {
    let block = client.latest_block().await?;
    let base_fee_per_gas = block.base_fee_per_gas.ok_or_else(|| {
        KairoxError::Session(SessionError::new(
            "chain does not report an EIP-1559 baseFeePerGas on its latest block",
        ))
    })?;
    // Best-effort: some nodes don't implement eth_maxPriorityFeePerGas.
    // Falling back to a fixed suggestion is safe because the safety caps
    // (and the required max_fee_per_gas >= base_fee invariant) still apply.
    let suggested_priority_fee = client.max_priority_fee_per_gas().await.ok();
    Ok(FeeHint {
        base_fee_per_gas,
        suggested_priority_fee,
        block,
    })
}

/// Best-effort pending nonce. `None` if the RPC call fails — the plan still
/// displays, with the nonce field reported as unavailable, since a nonce
/// read failing does not by itself make the mint unsafe to *plan* (only to
/// broadcast; this preview pipeline never broadcasts anything -- the live
/// send path re-fetches its own nonce fresh, strictly, in
/// [`crate::execution::prepared`]).
pub async fn fetch_nonce(client: &RpcClient, wallet: Address) -> Option<u64> {
    client.transaction_count(wallet).await.ok()
}

/// Best-effort gas estimate for the exact `mintPublic` calldata that would
/// be sent. Falls back to [`FALLBACK_GAS_LIMIT`] when estimation fails,
/// which is expected and normal when planning ahead of a stage's open time
/// (the call would revert on-chain today even though it will succeed once
/// the stage is active).
pub async fn fetch_gas_estimate(
    client: &RpcClient,
    from: Address,
    to: Address,
    data: &Bytes,
    value: U256,
) -> u64 {
    client
        .estimate_gas(from, to, data, value)
        .await
        .unwrap_or(FALLBACK_GAS_LIMIT)
}
