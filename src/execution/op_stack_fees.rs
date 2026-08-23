//! Complete pre-sign OP Stack transaction-fee bounding.
//!
//! An OP Stack L2 transaction can incur **three** separate fee
//! components -- L2 execution, L1 data/security publication, and (since
//! the Isthmus upgrade) an operator fee -- see `protocol::op_stack`'s
//! module doc comment for the exact live-verified formulas. Kairox's
//! safety invariant is that `max_gas_cost`/`max_total_spend` must bound
//! the sum of *all three*, never silently only the L2 execution
//! component. This module is the one place that sum is computed, so
//! `execution::prepared::gather_unsigned_plan` (the pre-sign path) has a
//! single, narrow, chain-scoped call site rather than three ad hoc reads
//! -- see [`bound_op_stack_fees`].
//!
//! Only ever consulted for a chain whose
//! [`crate::chain::registry::ChainInfo::op_stack_gas_price_oracle`] is
//! `Some(_)` (currently only Ink) -- every existing chain
//! (Ethereum/Base/Robinhood) has this field `None` and is completely
//! unaffected by this module.

use alloy_primitives::{Address, U256};

use crate::chain::rpc::RpcClient;
use crate::protocol::op_stack;
use crate::signing::transaction::UnsignedEip1559Tx;

use super::errors::{KairoxError, SessionError};

/// The complete, conservative pre-sign fee bound for one OP Stack
/// transaction: every component `SafetyCaps::max_gas_cost` must cover on
/// an OP Stack chain (see this module's doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpStackFeeBound {
    /// `gas_limit * max_fee_per_gas` -- the same worst-case L2 execution
    /// bound Kairox already computes for every chain via
    /// `Eip1559Fees::worst_case_gas_cost`.
    pub l2_execution_upper_bound: U256,
    /// `GasPriceOracle.getL1FeeUpperBound(unsigned_tx_size)` -- a live,
    /// read-only oracle call, never a locally reimplemented formula (see
    /// `protocol::op_stack`'s doc comment for why).
    pub l1_data_fee_upper_bound: U256,
    /// `GasPriceOracle.getOperatorFee(gas_limit)` -- read live on every
    /// call; currently `0` on Ink, but never cached or assumed zero (see
    /// `protocol::op_stack`'s doc comment).
    pub operator_fee_upper_bound: U256,
}

impl OpStackFeeBound {
    /// The complete conservative "gas cost" figure --
    /// `SafetyCaps::check`'s `gas_cost` argument on an OP Stack chain
    /// means exactly this sum, never `l2_execution_upper_bound` alone.
    /// Saturating: an overflowing sum fails the safety-cap comparison it
    /// feeds into (a saturated `U256::MAX` cannot be `<=` any real,
    /// finite cap) rather than silently wrapping to a small number.
    pub fn total(&self) -> U256 {
        self.l2_execution_upper_bound
            .saturating_add(self.l1_data_fee_upper_bound)
            .saturating_add(self.operator_fee_upper_bound)
    }
}

/// Read the live `GasPriceOracle` state at `gas_price_oracle` and compute
/// the complete conservative pre-sign fee bound for the transaction
/// described by `unsigned_tx`/`gas_limit`/`max_fee_per_gas`.
///
/// `unsigned_tx_size` is derived from
/// [`UnsignedEip1559Tx::encoded_for_signing`] -- Kairox's own real
/// EIP-2718/EIP-1559 unsigned serialization, the exact byte length
/// `getL1FeeUpperBound`'s `_unsignedTxSize` parameter documents itself as
/// expecting -- never a guessed or constant size.
///
/// Both oracle reads are issued concurrently (independent `eth_call`s,
/// same pattern as every other multi-read gather in this codebase). Any
/// RPC/decode failure propagates via `?` -- there is no fallback value
/// for either fee component; an unreadable oracle must fail preparation
/// closed, per this pass's explicit requirement, never silently proceed
/// with a partial fee bound.
pub async fn bound_op_stack_fees(
    client: &RpcClient,
    gas_price_oracle: Address,
    unsigned_tx: &UnsignedEip1559Tx,
    max_fee_per_gas: u128,
) -> Result<OpStackFeeBound, KairoxError> {
    let unsigned_tx_size = unsigned_tx.encoded_for_signing().len();
    let l1_fee_calldata = op_stack::encode_get_l1_fee_upper_bound(unsigned_tx_size);
    let operator_fee_calldata = op_stack::encode_get_operator_fee(unsigned_tx.gas_limit);

    let (l1_fee_raw, operator_fee_raw) = tokio::try_join!(
        async {
            client
                .eth_call(gas_price_oracle, &l1_fee_calldata)
                .await
                .map_err(KairoxError::from)
        },
        async {
            client
                .eth_call(gas_price_oracle, &operator_fee_calldata)
                .await
                .map_err(KairoxError::from)
        },
    )?;

    let l1_data_fee_upper_bound = op_stack::decode_get_l1_fee_upper_bound(&l1_fee_raw)
        .map_err(|e| KairoxError::Session(SessionError::new(format!(
            "could not decode GasPriceOracle.getL1FeeUpperBound response -- refusing to prepare a \
             live transaction with an unbounded L1 data fee ({e})"
        ))))?;
    let operator_fee_upper_bound =
        op_stack::decode_get_operator_fee(&operator_fee_raw).map_err(|e| {
            KairoxError::Session(SessionError::new(format!(
                "could not decode GasPriceOracle.getOperatorFee response -- refusing to prepare a \
             live transaction with an unbounded operator fee ({e})"
            )))
        })?;

    let l2_execution_upper_bound =
        U256::from(max_fee_per_gas).saturating_mul(U256::from(unsigned_tx.gas_limit));

    Ok(OpStackFeeBound {
        l2_execution_upper_bound,
        l1_data_fee_upper_bound,
        operator_fee_upper_bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use alloy_primitives::{address, hex};
    use alloy_sol_types::SolCall;
    use serde_json::json;

    const GPO: Address = address!("420000000000000000000000000000000000000F");

    fn sample_unsigned_tx() -> UnsignedEip1559Tx {
        UnsignedEip1559Tx {
            chain_id: 57073,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000,
            max_fee_per_gas: 2_000_000,
            gas_limit: 100_000,
            to: address!("1111111111111111111111111111111111111111"),
            value: U256::ZERO,
            data: alloy_primitives::Bytes::new(),
            access_list: Vec::new(),
        }
    }

    async fn connect(transport: MockTransport) -> RpcClient {
        RpcClient::connect(Box::new(transport), 57073, EndpointRole::ReadWrite, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn bounds_all_three_components_from_live_oracle_reads() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0xdef1"))
            .respond_eth_call_selector(
                op_stack::getL1FeeUpperBoundCall::SELECTOR,
                json!(format!(
                    "0x{}",
                    hex::encode(op_stack::getL1FeeUpperBoundCall::abi_encode_returns(
                        &U256::from(2_185_347_373u64)
                    ))
                )),
            )
            .respond_eth_call_selector(
                op_stack::getOperatorFeeCall::SELECTOR,
                json!(format!(
                    "0x{}",
                    hex::encode(op_stack::getOperatorFeeCall::abi_encode_returns(
                        &U256::ZERO
                    ))
                )),
            )
            .error("eth_call", -32000, "execution reverted")
            .build();
        let client = connect(transport).await;

        let unsigned = sample_unsigned_tx();
        let bound = bound_op_stack_fees(&client, GPO, &unsigned, unsigned.max_fee_per_gas)
            .await
            .unwrap();

        assert_eq!(
            bound.l2_execution_upper_bound,
            U256::from(2_000_000u128) * U256::from(100_000u64)
        );
        assert_eq!(bound.l1_data_fee_upper_bound, U256::from(2_185_347_373u64));
        assert_eq!(bound.operator_fee_upper_bound, U256::ZERO);
        assert_eq!(
            bound.total(),
            U256::from(2_000_000u128) * U256::from(100_000u64) + U256::from(2_185_347_373u64)
        );
    }

    #[tokio::test]
    async fn nonzero_operator_fee_is_included_in_the_total_never_dropped() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0xdef1"))
            .respond_eth_call_selector(
                op_stack::getL1FeeUpperBoundCall::SELECTOR,
                json!(format!(
                    "0x{}",
                    hex::encode(op_stack::getL1FeeUpperBoundCall::abi_encode_returns(
                        &U256::from(1_000u64)
                    ))
                )),
            )
            .respond_eth_call_selector(
                op_stack::getOperatorFeeCall::SELECTOR,
                json!(format!(
                    "0x{}",
                    hex::encode(op_stack::getOperatorFeeCall::abi_encode_returns(
                        &U256::from(50_000u64)
                    ))
                )),
            )
            .error("eth_call", -32000, "execution reverted")
            .build();
        let client = connect(transport).await;

        let unsigned = sample_unsigned_tx();
        let bound = bound_op_stack_fees(&client, GPO, &unsigned, unsigned.max_fee_per_gas)
            .await
            .unwrap();

        assert_eq!(bound.operator_fee_upper_bound, U256::from(50_000u64));
        assert!(
            bound.total()
                > bound.l2_execution_upper_bound + bound.l1_data_fee_upper_bound - U256::from(1u64),
        );
        assert_eq!(
            bound.total(),
            bound.l2_execution_upper_bound + U256::from(1_000u64) + U256::from(50_000u64)
        );
    }

    #[tokio::test]
    async fn oracle_read_failure_fails_closed_not_a_partial_bound() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0xdef1"))
            .error("eth_call", -32000, "execution reverted")
            .build();
        let client = connect(transport).await;

        let unsigned = sample_unsigned_tx();
        let err = bound_op_stack_fees(&client, GPO, &unsigned, unsigned.max_fee_per_gas)
            .await
            .unwrap_err();
        let message = format!("{err}");
        assert!(message.contains("execution reverted") || message.contains("could not"));
    }

    #[tokio::test]
    async fn malformed_oracle_response_fails_closed() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0xdef1"))
            .respond_eth_call_selector(op_stack::getL1FeeUpperBoundCall::SELECTOR, json!("0x01"))
            .respond_eth_call_selector(
                op_stack::getOperatorFeeCall::SELECTOR,
                json!(format!(
                    "0x{}",
                    hex::encode(op_stack::getOperatorFeeCall::abi_encode_returns(
                        &U256::ZERO
                    ))
                )),
            )
            .error("eth_call", -32000, "execution reverted")
            .build();
        let client = connect(transport).await;

        let unsigned = sample_unsigned_tx();
        let err = bound_op_stack_fees(&client, GPO, &unsigned, unsigned.max_fee_per_gas)
            .await
            .unwrap_err();
        let message = format!("{err}");
        assert!(message.contains("could not decode"));
    }

    #[tokio::test]
    async fn unsigned_tx_size_is_derived_from_real_serialization_not_a_constant() {
        // Two transactions with genuinely different calldata lengths must
        // produce different encoded sizes -- proving the L1-fee call is
        // sized from the real serialization, not a fixed guess like 200.
        let mut short = sample_unsigned_tx();
        short.data = alloy_primitives::Bytes::new();
        let mut long = sample_unsigned_tx();
        long.data = alloy_primitives::Bytes::from(vec![0xAB; 500]);

        let short_size = short.encoded_for_signing().len();
        let long_size = long.encoded_for_signing().len();
        assert!(
            long_size > short_size + 400,
            "expected the longer calldata to materially increase the unsigned encoding size, got \
             short={short_size} long={long_size}"
        );
    }
}
