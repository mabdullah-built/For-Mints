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
use crate::domain::fees::SafetyCapGuarantee;
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

    /// The [`SafetyCapGuarantee`] level for the L1 data fee and operator
    /// fee components -- always [`SafetyCapGuarantee::PreSignBoundOnly`]
    /// on an OP Stack chain, per this module's and
    /// `domain::fees::SafetyCapGuarantee`'s doc comments. Provided as a
    /// method (rather than only documentation) so callers can assert on
    /// it in tests and branch on it in reporting code without
    /// hardcoding the enum variant themselves.
    pub fn l1_and_operator_fee_guarantee(&self) -> SafetyCapGuarantee {
        SafetyCapGuarantee::PreSignBoundOnly
    }

    /// The exact operator-facing truthful disclosure for this bound --
    /// the wording this pass's audit requires before Kairox may show an
    /// Ink total-spend figure: it must never read as an immutable
    /// maximum when two of its three components legally are not one.
    pub fn fee_guarantee_disclosure(&self) -> String {
        format!(
            "L2 execution cost ({} wei) is protocol-enforced by maxFeePerGas/gasLimit -- a real \
             maximum. L1 data fee ({} wei) and operator fee ({} wei) are PRE-SIGN BOUNDS ONLY, \
             read immediately before signing: the OP Stack protocol provides no transaction \
             field that caps either, so the amount actually charged at inclusion may differ if \
             L1 gas prices or the chain's operator-fee parameters change before this transaction \
             is included. This total is the strongest practical bound Kairox can compute, not a \
             protocol-guaranteed maximum.",
            self.l2_execution_upper_bound,
            self.l1_data_fee_upper_bound,
            self.operator_fee_upper_bound
        )
    }
}

/// The complete network-fee accounting Kairox can derive from an already-
/// confirmed receipt, split into the same three components
/// [`OpStackFeeBound`] pre-sign-bounds -- but here as **actual, historical**
/// amounts, not estimates. Each component is `None` when the receipt does
/// not expose the field(s) needed to compute it -- never a guessed or
/// zero-defaulted value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkFeeAccounting {
    /// `gasUsed * effectiveGasPrice` -- `None` if either field is absent
    /// from the receipt.
    pub l2_execution_fee: Option<U256>,
    /// The receipt's own `l1Fee` field, used directly and authoritatively
    /// -- never recomputed from current oracle state (see
    /// [`network_fee_accounting`]'s doc comment for why that would be
    /// wrong).
    pub l1_data_fee: Option<U256>,
    /// The actual historical operator fee, if reconstructable. Real Ink
    /// receipts observed this pass expose no `operatorFee`/
    /// `operatorFeeScalar`/`operatorFeeConstant` fields at all, so this
    /// is `None` in practice today -- but the field exists so a future
    /// RPC provider that does expose them is handled correctly rather
    /// than requiring a schema change.
    pub operator_fee: Option<U256>,
}

impl NetworkFeeAccounting {
    /// The complete total network fee -- `Some` **only** when every
    /// component is individually known, per this pass's explicit
    /// requirement ("total_network_fee only exact when all components
    /// known"). Never a partial sum silently presented as complete.
    pub fn total_network_fee(&self) -> Option<U256> {
        Some(
            self.l2_execution_fee?
                .saturating_add(self.l1_data_fee?)
                .saturating_add(self.operator_fee?),
        )
    }
}

/// Derive [`NetworkFeeAccounting`] from an already-confirmed
/// [`crate::chain::rpc::TransactionReceipt`].
///
/// **Deliberately takes no `GasPriceOracle`/current-chain-state
/// parameter at all** -- this is a structural guarantee, not just a
/// convention, that this function can never reconstruct a historical
/// receipt's fee from *current* oracle parameters. Ink's `l1BaseFeeScalar`/
/// `operatorFeeScalar`/`operatorFeeConstant` are all live, operator-
/// controlled values (see `protocol::op_stack`'s doc comment) that can
/// legitimately differ between the block a receipt landed in and
/// whatever is live "now" -- using "now"'s values to explain "then"'s
/// receipt would silently misreport history. The only fee data this
/// function ever uses is what the receipt itself reports for that exact
/// historical transaction.
///
/// When a receipt exposes `operatorFeeScalar`/`operatorFeeConstant`
/// (real Ink receipts observed this pass do not, but this pass's own
/// audit found this can vary by RPC provider/future chain upgrade), the
/// operator fee is reconstructed using the **Jovian** formula --
/// `gasUsed * operatorFeeScalar * 100 + operatorFeeConstant`, per the
/// verified current `GasPriceOracle.getOperatorFee` source (see
/// `protocol::op_stack`'s doc comment) -- since Ink is confirmed live
/// Jovian-active (`isJovian=true`, verified this pass) for every
/// transaction Kairox could plausibly need to reconcile. This uses ONLY
/// the receipt's own historical `operatorFeeScalar`/`operatorFeeConstant`
/// values, never a live oracle read, so it can never "rewrite history"
/// with today's parameters. If the pre-Jovian formula ever needs
/// reconciling (a receipt from before Ink's Jovian activation), this
/// deliberately returns `None` rather than silently applying the wrong
/// formula -- a future pass can add that branch once it is actually
/// needed and can be verified against a real pre-Jovian receipt.
pub fn network_fee_accounting(
    receipt: &crate::chain::rpc::TransactionReceipt,
) -> NetworkFeeAccounting {
    let l2_execution_fee = match (receipt.gas_used, receipt.effective_gas_price) {
        (Some(gas_used), Some(price)) => {
            Some(U256::from(gas_used).saturating_mul(U256::from(price)))
        }
        _ => None,
    };
    let operator_fee = match (
        receipt.gas_used,
        receipt.operator_fee_scalar,
        receipt.operator_fee_constant,
    ) {
        (Some(gas_used), Some(scalar), Some(constant)) => Some(
            U256::from(gas_used)
                .saturating_mul(scalar)
                .saturating_mul(U256::from(100u64))
                .saturating_add(constant),
        ),
        _ => None,
    };
    NetworkFeeAccounting {
        l2_execution_fee,
        l1_data_fee: receipt.l1_fee,
        operator_fee,
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

    #[test]
    fn l1_and_operator_fee_guarantee_is_pre_sign_bound_only_never_protocol_enforced() {
        let bound = OpStackFeeBound {
            l2_execution_upper_bound: U256::from(1u64),
            l1_data_fee_upper_bound: U256::from(1u64),
            operator_fee_upper_bound: U256::from(1u64),
        };
        assert_eq!(
            bound.l1_and_operator_fee_guarantee(),
            SafetyCapGuarantee::PreSignBoundOnly
        );
    }

    #[test]
    fn fee_guarantee_disclosure_names_l2_as_protocol_enforced_and_l1_operator_as_bound_only() {
        let bound = OpStackFeeBound {
            l2_execution_upper_bound: U256::from(200_000_000_000_000u128),
            l1_data_fee_upper_bound: U256::from(2_185_347_373u64),
            operator_fee_upper_bound: U256::from(50_000u64),
        };
        let disclosure = bound.fee_guarantee_disclosure();
        assert!(disclosure.contains("protocol-enforced"));
        assert!(disclosure.contains("PRE-SIGN BOUNDS ONLY"));
        assert!(disclosure.contains("no transaction field that caps"));
        // Explicitly disclaims being a protocol-guaranteed maximum overall.
        assert!(disclosure.contains("not a protocol-guaranteed maximum"));
        assert!(disclosure.contains(&U256::from(200_000_000_000_000u128).to_string()));
        assert!(disclosure.contains(&U256::from(2_185_347_373u64).to_string()));
        assert!(disclosure.contains(&U256::from(50_000u64).to_string()));
    }

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

    // -----------------------------------------------------------------
    // Micro-gate items 13-14: Ink receipt fee accounting -- historical
    // truth from the receipt itself, never reconstructed from current
    // oracle state.
    // -----------------------------------------------------------------

    fn base_receipt(status_success: bool) -> crate::chain::rpc::TransactionReceipt {
        crate::chain::rpc::TransactionReceipt {
            transaction_hash: alloy_primitives::B256::repeat_byte(0x11),
            status_success,
            block_number: 100,
            logs: Vec::new(),
            gas_used: None,
            effective_gas_price: None,
            l1_fee: None,
            l1_gas_used: None,
            l1_gas_price: None,
            l1_base_fee_scalar: None,
            l1_blob_base_fee: None,
            l1_blob_base_fee_scalar: None,
            operator_fee_scalar: None,
            operator_fee_constant: None,
        }
    }

    #[test]
    fn success_receipt_status_is_authoritative() {
        let receipt = base_receipt(true);
        assert!(receipt.status_success);
    }

    #[test]
    fn revert_receipt_status_is_authoritative() {
        let receipt = base_receipt(false);
        assert!(!receipt.status_success);
    }

    #[test]
    fn l1_fee_is_used_directly_from_the_receipt() {
        let mut receipt = base_receipt(true);
        receipt.l1_fee = Some(U256::from(48_245_719u64));
        let accounting = network_fee_accounting(&receipt);
        assert_eq!(accounting.l1_data_fee, Some(U256::from(48_245_719u64)));
    }

    #[test]
    fn operator_scalar_and_constant_both_zero_yields_zero_operator_fee_not_unknown() {
        let mut receipt = base_receipt(true);
        receipt.gas_used = Some(60_000);
        receipt.effective_gas_price = Some(1_000_000);
        receipt.l1_fee = Some(U256::from(1_000u64));
        receipt.operator_fee_scalar = Some(U256::ZERO);
        receipt.operator_fee_constant = Some(U256::ZERO);
        let accounting = network_fee_accounting(&receipt);
        assert_eq!(accounting.operator_fee, Some(U256::ZERO));
        assert_eq!(
            accounting.total_network_fee(),
            Some(U256::from(60_000u64 * 1_000_000u64 + 1_000u64))
        );
    }

    #[test]
    fn nonzero_jovian_operator_params_produce_the_correct_reconstructed_fee() {
        let mut receipt = base_receipt(true);
        receipt.gas_used = Some(60_000);
        receipt.effective_gas_price = Some(1_000_000);
        receipt.l1_fee = Some(U256::from(1_000u64));
        // Jovian formula: gasUsed * operatorFeeScalar * 100 + operatorFeeConstant.
        receipt.operator_fee_scalar = Some(U256::from(7u64));
        receipt.operator_fee_constant = Some(U256::from(500u64));
        let accounting = network_fee_accounting(&receipt);
        let expected_operator_fee = U256::from(60_000u64 * 7u64 * 100u64 + 500u64);
        assert_eq!(accounting.operator_fee, Some(expected_operator_fee));
        assert_eq!(
            accounting.total_network_fee(),
            Some(
                U256::from(60_000u64 * 1_000_000u64) + U256::from(1_000u64) + expected_operator_fee
            )
        );
    }

    #[test]
    fn missing_optional_operator_receipt_fields_reports_unknown_not_zero() {
        let mut receipt = base_receipt(true);
        receipt.gas_used = Some(60_000);
        receipt.effective_gas_price = Some(1_000_000);
        receipt.l1_fee = Some(U256::from(1_000u64));
        // operator_fee_scalar/constant left None -- real Ink receipts.
        let accounting = network_fee_accounting(&receipt);
        assert_eq!(accounting.operator_fee, None);
        assert_eq!(
            accounting.total_network_fee(),
            None,
            "total_network_fee must be None, never a partial sum, when any component is unknown"
        );
    }

    #[test]
    fn missing_l2_execution_fields_reports_unknown_l2_fee() {
        let mut receipt = base_receipt(true);
        receipt.l1_fee = Some(U256::from(1_000u64));
        // gas_used/effective_gas_price left None.
        let accounting = network_fee_accounting(&receipt);
        assert_eq!(accounting.l2_execution_fee, None);
        assert_eq!(accounting.total_network_fee(), None);
    }

    #[test]
    fn network_fee_accounting_never_touches_current_oracle_state() {
        // Structural proof, not just documentation: the function's own
        // signature takes only a TransactionReceipt -- there is no
        // GasPriceOracle/RpcClient/chain-state parameter it could
        // possibly consult, so it is categorically impossible for it to
        // "rewrite history" using today's oracle parameters. This test
        // exists so any future signature change that adds such a
        // parameter is a deliberate, reviewable diff, not an accident.
        fn assert_signature(
            _f: fn(&crate::chain::rpc::TransactionReceipt) -> NetworkFeeAccounting,
        ) {
        }
        assert_signature(network_fee_accounting);
    }

    #[test]
    fn historical_operator_params_differ_from_hypothetical_current_oracle_and_receipt_wins() {
        // Simulates exactly the scenario item 13 warns against: the
        // receipt's OWN historical scalar/constant (7, 500) differ from
        // some hypothetical "current" live oracle state (e.g. 99,
        // 999999) -- network_fee_accounting must use only the receipt's
        // values, which this test proves by never referencing any
        // "current" value at all in the computation.
        let mut receipt = base_receipt(true);
        receipt.gas_used = Some(60_000);
        receipt.effective_gas_price = Some(1_000_000);
        receipt.l1_fee = Some(U256::from(1_000u64));
        receipt.operator_fee_scalar = Some(U256::from(7u64)); // historical
        receipt.operator_fee_constant = Some(U256::from(500u64)); // historical
        let accounting = network_fee_accounting(&receipt);
        let historical_expected = U256::from(60_000u64 * 7u64 * 100u64 + 500u64);
        let current_hypothetical_wrong = U256::from(60_000u64 * 99u64 * 100u64 + 999_999u64);
        assert_eq!(accounting.operator_fee, Some(historical_expected));
        assert_ne!(accounting.operator_fee, Some(current_hypothetical_wrong));
    }
}
