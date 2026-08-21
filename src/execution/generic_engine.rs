//! Generic verified ERC-721/ERC-1155 mint execution.
//!
//! Activates only for a [`GenericMintSchema`] the operator explicitly
//! declared and that on-chain ERC-165 corroborates (see
//! `cli::commands::resolver_adapters::GenericVerifiedContractAdapter`) --
//! never a guessed selector. Everything after calldata construction reuses
//! the exact same primitives the SeaDrop PUBLIC engine's
//! [`super::prepared::finalize_signed_transaction`] uses (`UnsignedEip1559Tx`,
//! `PreparedBroadcast`), and receipt truth reuses
//! [`super::receipt::poll_receipt`]/[`crate::protocol::logs::extract_minted_assets`]
//! unchanged -- both were already fully generic (standard-agnostic within
//! `Transfer`/`TransferSingle`), so no new receipt-verification code exists
//! here at all.
//!
//! Known limitation: `extract_minted_assets` does not yet decode
//! `TransferBatch`, so a batch (quantity > 1 in one `TransferBatch` event)
//! ERC-1155 mint is not verified by this pass -- single-id, single-event
//! mints only. See `docs/generic-engine.md`.

use alloy_primitives::{Address, Bytes, U256, keccak256};
use alloy_sol_types::SolCall;
use time::OffsetDateTime;

use crate::chain::registry::ChainInfo;
use crate::chain::rpc::{PreparedBroadcast, RpcClient};
use crate::domain::fees::{Eip1559Fees, SafetyCaps, worst_case_total_spend};
use crate::signing::signer::Signer;
use crate::signing::transaction::UnsignedEip1559Tx;

use super::errors::{KairoxError, SessionError, SessionErrorKind};
use super::generic_schema::{GenericMintSchema, GenericMintShape};
use super::prepared::PreparedTransaction;

#[derive(Debug, Clone)]
pub struct GenericMintRequest {
    pub chain: ChainInfo,
    pub collection: Address,
    pub wallet: Address,
    pub quantity: u64,
    pub schema: GenericMintSchema,
    pub gas_buffer_multiplier: f64,
    pub safety_caps: SafetyCaps,
}

/// Builds calldata for exactly the schema's declared shape. Each arm is
/// its own `sol!` invocation in its own scope so overlapping Solidity
/// function names (`mint` appears in three of the four shapes, with
/// different argument lists / selectors) never collide as Rust identifiers
/// -- the derived 4-byte selector is unaffected by that scoping and is
/// exactly what the real Solidity signature would hash to.
pub fn encode_calldata(
    schema: &GenericMintSchema,
    wallet: Address,
    quantity: u64,
) -> Result<Bytes, KairoxError> {
    schema.validate().map_err(|e| {
        KairoxError::Session(SessionError::new(format!("invalid generic schema: {e}")))
    })?;
    let quantity = U256::from(quantity);
    match schema.shape {
        GenericMintShape::MintQuantity => {
            mod abi {
                alloy_sol_types::sol! { function mint(uint256 quantity) external payable; }
            }
            Ok(abi::mintCall { quantity }.abi_encode().into())
        }
        GenericMintShape::PublicMintQuantity => {
            mod abi {
                alloy_sol_types::sol! { function publicMint(uint256 quantity) external payable; }
            }
            Ok(abi::publicMintCall { quantity }.abi_encode().into())
        }
        GenericMintShape::MintToQuantity => {
            mod abi {
                alloy_sol_types::sol! { function mint(address to, uint256 quantity) external payable; }
            }
            Ok(abi::mintCall {
                to: wallet,
                quantity,
            }
            .abi_encode()
            .into())
        }
        GenericMintShape::MintIdQuantity => {
            mod abi {
                alloy_sol_types::sol! { function mint(uint256 id, uint256 quantity) external payable; }
            }
            let id = schema.token_id.ok_or_else(|| {
                KairoxError::Session(SessionError::new(
                    "generic schema: mint_id_quantity requires token_id",
                ))
            })?;
            Ok(abi::mintCall {
                id: U256::from(id),
                quantity,
            }
            .abi_encode()
            .into())
        }
    }
}

/// Preflight classification for the `eth_estimateGas` call this engine
/// makes before signing. There is no stage-timing model for a generic
/// contract in this pass (see module docs), so `EXPECTED_PRESTART_REVERT`
/// is never produced here -- only [`SimulationOutcome::Pass`] or
/// [`SimulationOutcome::DefinitiveRevert`] -- unlike the fuller taxonomy
/// `docs/generic-engine.md` describes for a future stage-aware version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationOutcome {
    Pass,
    DefinitiveRevert,
}

/// Gather fresh live state, validate, simulate (`eth_estimateGas`), sign,
/// and serialize a generic mint transaction. Fails closed on any missing
/// or invalid required input or a definitive simulation revert -- mirrors
/// [`super::prepared::prepare_live_transaction`]'s guarantees exactly, for
/// a target whose calldata comes from an operator-verified schema instead
/// of the fixed SeaDrop ABI.
pub async fn prepare_generic_transaction(
    client: &RpcClient,
    signer: &dyn Signer,
    request: &GenericMintRequest,
) -> Result<PreparedTransaction, KairoxError> {
    if signer.address() != request.wallet {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::WalletKeyMismatch,
            format!(
                "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
                signer.address(),
                request.wallet
            ),
        )));
    }

    let calldata = encode_calldata(&request.schema, request.wallet, request.quantity)?;

    let price_per_token: U256 = request.schema.price_per_token_wei.parse().map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "generic schema: invalid price_per_token_wei: {e}"
        )))
    })?;
    let mint_value = price_per_token.saturating_mul(U256::from(request.quantity));

    let block = client.latest_block().await?;
    let base_fee_per_gas = block.base_fee_per_gas.ok_or_else(|| {
        KairoxError::Session(SessionError::new(
            "chain does not report an EIP-1559 baseFeePerGas; cannot safely price a live transaction",
        ))
    })?;
    let max_priority_fee_per_gas = client.max_priority_fee_per_gas().await?;
    let max_fee_per_gas = base_fee_per_gas
        .saturating_mul(2)
        .saturating_add(max_priority_fee_per_gas);
    let fees = Eip1559Fees::new(base_fee_per_gas, max_priority_fee_per_gas, max_fee_per_gas)?;

    let nonce = client.transaction_count(request.wallet).await?;
    let balance = client.get_balance(request.wallet).await?;

    let gas_estimate = client
        .estimate_gas(request.wallet, request.collection, &calldata, mint_value)
        .await
        .map_err(|_| {
            // A revert during simulation is a DEFINITIVE_REVERT for a
            // generic contract -- there is no "stage not open yet" model
            // to excuse it under in this pass (see module docs), so it
            // stops the session here rather than being signed.
            KairoxError::Session(SessionError::new(
                "generic mint simulation (eth_estimateGas) reverted: DEFINITIVE_REVERT; refusing to sign",
            ))
        })?;
    let gas_limit = ((gas_estimate as f64) * request.gas_buffer_multiplier.max(1.0)).ceil() as u64;

    let worst_case_gas_cost = fees.worst_case_gas_cost(gas_limit);
    let worst_case_total = worst_case_total_spend(mint_value, worst_case_gas_cost);

    request
        .safety_caps
        .check(mint_value, worst_case_gas_cost, worst_case_total)?;

    if balance < worst_case_total {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::InsufficientBalance,
            format!(
                "wallet balance {balance} wei is insufficient for worst-case total spend {worst_case_total} wei"
            ),
        )));
    }

    let unsigned = UnsignedEip1559Tx {
        chain_id: request.chain.chain_id,
        nonce,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        max_fee_per_gas: fees.max_fee_per_gas(),
        gas_limit,
        to: request.collection,
        value: mint_value,
        data: calldata.clone(),
        access_list: Vec::new(),
    };
    let signing_hash = unsigned.signing_hash();
    let signed = signer
        .sign_transaction(unsigned)
        .map_err(KairoxError::Signing)?;
    let raw_signed_bytes = signed.raw_bytes();
    let tx_hash = signed.tx_hash();

    let broadcast_prepare_started = std::time::Instant::now();
    let broadcast = PreparedBroadcast::build(tx_hash, raw_signed_bytes.clone());
    let broadcast_prepare_ms = broadcast_prepare_started.elapsed().as_millis() as u64;

    Ok(PreparedTransaction {
        chain_id: request.chain.chain_id,
        wallet: request.wallet,
        nonce,
        target: request.collection,
        value: mint_value,
        calldata_hash: keccak256(&calldata),
        quantity: request.quantity,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        stage_start: OffsetDateTime::now_utc(),
        signing_hash,
        raw_signed_bytes,
        tx_hash,
        broadcast,
        broadcast_prepare_ms,
        prepared_at: OffsetDateTime::now_utc(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::generic_schema::GenericStandard;
    fn schema(shape: GenericMintShape, token_id: Option<u64>) -> GenericMintSchema {
        GenericMintSchema {
            standard: GenericStandard::Erc721,
            shape,
            token_id,
            price_per_token_wei: "10000000000000000".to_string(),
        }
    }

    fn wallet() -> Address {
        Address::from([1u8; 20])
    }

    #[test]
    fn mint_quantity_encodes_the_real_mint_uint256_selector() {
        let calldata =
            encode_calldata(&schema(GenericMintShape::MintQuantity, None), wallet(), 3).unwrap();
        mod real_abi {
            alloy_sol_types::sol! { function mint(uint256 quantity) external payable; }
        }
        assert_eq!(&calldata[0..4], real_abi::mintCall::SELECTOR);
    }

    #[test]
    fn public_mint_quantity_encodes_the_real_public_mint_selector() {
        let calldata = encode_calldata(
            &schema(GenericMintShape::PublicMintQuantity, None),
            wallet(),
            1,
        )
        .unwrap();
        mod real_abi {
            alloy_sol_types::sol! { function publicMint(uint256 quantity) external payable; }
        }
        assert_eq!(&calldata[0..4], real_abi::publicMintCall::SELECTOR);
    }

    #[test]
    fn mint_to_quantity_encodes_recipient_and_quantity_in_the_right_positions() {
        let calldata =
            encode_calldata(&schema(GenericMintShape::MintToQuantity, None), wallet(), 2).unwrap();
        mod real_abi {
            alloy_sol_types::sol! { function mint(address to, uint256 quantity) external payable; }
        }
        assert_eq!(&calldata[0..4], real_abi::mintCall::SELECTOR);
        let decoded = real_abi::mintCall::abi_decode(&calldata).unwrap();
        assert_eq!(decoded.to, wallet());
        assert_eq!(decoded.quantity, U256::from(2u64));
    }

    #[test]
    fn mint_id_quantity_requires_token_id_and_encodes_it() {
        let err = encode_calldata(&schema(GenericMintShape::MintIdQuantity, None), wallet(), 1);
        assert!(err.is_err());

        let calldata = encode_calldata(
            &schema(GenericMintShape::MintIdQuantity, Some(42)),
            wallet(),
            1,
        )
        .unwrap();
        mod real_abi {
            alloy_sol_types::sol! { function mint(uint256 id, uint256 quantity) external payable; }
        }
        let decoded = real_abi::mintCall::abi_decode(&calldata).unwrap();
        assert_eq!(decoded.id, U256::from(42u64));
        assert_eq!(decoded.quantity, U256::from(1u64));
    }
}
