//! The live (`--send`) transaction-preparation pipeline.
//!
//! Unlike [`crate::execution::plan::build_plan`] (which is dry-run-safe and
//! deliberately tolerates missing/estimated data with conservative
//! fallbacks), everything here requires successful, fresh retrieval of live
//! chain state. Any required read failing — nonce, balance, base fee,
//! priority fee, gas estimate/simulation, mint price, stage state,
//! allocation, supply, fee recipient validity — fails the whole
//! preparation closed. There is no fallback constant anywhere in this
//! module.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use time::OffsetDateTime;

use crate::chain::registry::{ChainId, ChainInfo};
use crate::chain::rpc::{PreparedBroadcast, RpcClient};
use crate::domain::fees::{Eip1559Fees, SafetyCaps, worst_case_total_spend};
use crate::domain::timing::StageStatus;
use crate::protocol::seadrop::{self, encode_mint_public, select_fee_recipient};
use crate::signing::signer::Signer;
use crate::signing::transaction::UnsignedEip1559Tx;

use super::errors::{KairoxError, SessionError, SessionErrorKind};
use super::plan::PlanInputs;
use super::plan::build_plan;

/// A fully signed, ready-to-broadcast transaction plus the validated
/// metadata that produced it. Contains no secret key material — only the
/// public outputs of signing.
#[derive(Debug, Clone)]
pub struct PreparedTransaction {
    pub chain_id: ChainId,
    pub wallet: Address,
    pub nonce: u64,
    pub target: Address,
    pub value: U256,
    pub calldata_hash: B256,
    pub quantity: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub stage_start: OffsetDateTime,
    pub signing_hash: B256,
    pub raw_signed_bytes: Bytes,
    pub tx_hash: B256,
    /// The fully prebuilt broadcast payload for this transaction — built
    /// once, here, before the stage-open wait. The T=0 hot path only ever
    /// reads `broadcast.json_rpc_body`.
    pub broadcast: PreparedBroadcast,
    /// How long [`PreparedBroadcast::build`] took — hex-encoding plus JSON
    /// serialization, measured once, ahead of time.
    pub broadcast_prepare_ms: u64,
    pub prepared_at: OffsetDateTime,
}

/// Everything [`prepare_live_transaction`] needs to reach into chain state
/// for. Grouped so call sites (the scheduler) stay readable.
#[derive(Debug, Clone)]
pub struct LiveMintRequest {
    pub chain: ChainInfo,
    pub nft_contract: Address,
    pub seadrop_contract: Address,
    pub wallet: Address,
    pub quantity: u64,
    pub preferred_fee_recipient: Option<Address>,
    pub gas_buffer_multiplier: f64,
    pub safety_caps: SafetyCaps,
}

/// Everything [`gather_unsigned_plan`] validates and computes from fresh
/// live chain state, before any signing happens. Carries the exact
/// worst-case total spend Kairox computed for this one wallet — the number
/// a multi-wallet aggregate spend cap must be checked against, using real
/// post-gas-estimate costs rather than a declared upper bound, and checked
/// strictly before any wallet in the session is signed.
#[derive(Debug, Clone)]
pub struct PreparedUnsignedPlan {
    chain: ChainInfo,
    wallet: Address,
    nonce: u64,
    seadrop_contract: Address,
    mint_value: U256,
    calldata: Bytes,
    quantity: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    stage_start: OffsetDateTime,
    pub worst_case_total_spend: U256,
}

/// Gather fresh live state and validate every Phase-2 safety invariant —
/// everything [`prepare_live_transaction`] does except the actual signing.
/// Fails closed on any missing or invalid required input, exactly like the
/// combined function. Split out so a multi-wallet session can compute every
/// eligible wallet's real, finalized worst-case cost and check an aggregate
/// session spend cap *before* any wallet is signed (see
/// [`finalize_signed_transaction`]) — signing is the one step that must
/// never happen ahead of that check.
///
/// `signer_address` is only compared against `request.wallet` (a public
/// key check, not a signing operation) so a wrong-key wallet still fails
/// fast, before spending any RPC round trip, exactly as the combined
/// function always has.
pub async fn gather_unsigned_plan(
    client: &RpcClient,
    signer_address: Address,
    request: &LiveMintRequest,
) -> Result<PreparedUnsignedPlan, KairoxError> {
    if signer_address != request.wallet {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::WalletKeyMismatch,
            format!(
                "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
                signer_address, request.wallet
            ),
        )));
    }

    // Required on-chain reads: SeaDrop public-drop config, allowed fee
    // recipients, per-wallet/collection mint stats, latest block (for base
    // fee), priority fee, nonce, and balance. None of these seven reads
    // has a data dependency on any of the others -- only the *values*
    // combine afterward (allowed_fee_recipients + public_drop ->
    // fee_recipient -> calldata; block + priority fee -> fees; balance +
    // worst-case cost -> the insufficient-balance check). Issued
    // concurrently instead of one at a time for the same reason as
    // `opensea_engine::prepare_opensea_wallet_unsigned`'s identical
    // optimization (see its doc comment and
    // `tests::parallel_reads_take_the_slowest_call_not_the_sum` below for
    // the deterministic proof). Any RpcError here propagates via `?` — no
    // fallback.
    let public_drop_calldata = seadrop::encode_get_public_drop(request.nft_contract)?;
    let allowed_calldata = seadrop::encode_get_allowed_fee_recipients(request.nft_contract)?;
    let mint_stats_calldata = seadrop::encode_get_mint_stats(request.wallet);

    let (
        public_drop_raw,
        allowed_raw,
        mint_stats_raw,
        block,
        max_priority_fee_per_gas,
        nonce,
        balance,
    ) = tokio::try_join!(
        async {
            client
                .eth_call(request.seadrop_contract, &public_drop_calldata)
                .await
                .map_err(KairoxError::from)
        },
        async {
            client
                .eth_call(request.seadrop_contract, &allowed_calldata)
                .await
                .map_err(KairoxError::from)
        },
        async {
            client
                .eth_call(request.nft_contract, &mint_stats_calldata)
                .await
                .map_err(KairoxError::from)
        },
        async { client.latest_block().await.map_err(KairoxError::from) },
        async {
            client
                .max_priority_fee_per_gas()
                .await
                .map_err(KairoxError::from)
        },
        async {
            client
                .transaction_count(request.wallet)
                .await
                .map_err(KairoxError::from)
        },
        async {
            client
                .get_balance(request.wallet)
                .await
                .map_err(KairoxError::from)
        },
    )?;

    let public_drop = seadrop::decode_get_public_drop(&public_drop_raw)?;
    let allowed_fee_recipients = seadrop::decode_get_allowed_fee_recipients(&allowed_raw)?;
    let mint_stats = seadrop::decode_get_mint_stats(&mint_stats_raw)?;

    let fee_recipient = select_fee_recipient(
        &allowed_fee_recipients,
        public_drop.restrict_fee_recipients,
        request.preferred_fee_recipient,
        request.wallet,
    )?;

    let base_fee_per_gas = block.base_fee_per_gas.ok_or_else(|| {
        KairoxError::Session(SessionError::new(
            "chain does not report an EIP-1559 baseFeePerGas; cannot safely price a live transaction"
                ,
        ))
    })?;
    let max_fee_per_gas = base_fee_per_gas
        .saturating_mul(2)
        .saturating_add(max_priority_fee_per_gas);
    // Constructing this also enforces max_fee_per_gas >= base_fee and
    // max_priority_fee_per_gas <= max_fee_per_gas.
    let fees = Eip1559Fees::new(base_fee_per_gas, max_priority_fee_per_gas, max_fee_per_gas)?;

    let mint_value = public_drop
        .mint_price
        .saturating_mul(U256::from(request.quantity));
    let calldata = encode_mint_public(
        request.nft_contract,
        fee_recipient,
        Address::ZERO,
        request.quantity,
    )?;

    // Required gas estimate/simulation. `eth_estimateGas` reverting or
    // erroring is NOT tolerated here (unlike the dry-run gather path) —
    // propagate directly, which fails preparation closed.
    let gas_estimate = client
        .estimate_gas(
            request.wallet,
            request.seadrop_contract,
            &calldata,
            mint_value,
        )
        .await?;
    let gas_limit = ((gas_estimate as f64) * request.gas_buffer_multiplier.max(1.0)).ceil() as u64;

    let inputs = PlanInputs {
        chain: request.chain.clone(),
        nft_contract: request.nft_contract,
        seadrop_contract: request.seadrop_contract,
        minter_address: request.wallet,
        quantity: request.quantity,
        public_drop,
        allowed_fee_recipients,
        preferred_fee_recipient: request.preferred_fee_recipient,
        wallet_already_minted: mint_stats.minter_num_minted,
        current_total_supply: mint_stats.current_total_supply,
        max_supply: Some(mint_stats.max_supply),
        nonce: Some(nonce),
        base_fee_per_gas: fees.base_fee_per_gas(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        max_fee_per_gas: fees.max_fee_per_gas(),
        gas_estimate,
        gas_limit,
        safety_caps: request.safety_caps,
        now: OffsetDateTime::now_utc(),
    };

    let plan = build_plan(inputs)?;

    // A live preparation must never target an already-closed stage. (A
    // not-yet-started stage is expected and normal — the scheduler is
    // preparing ahead of the stage opening — so only `Ended` is rejected
    // here.)
    if matches!(plan.stage_status, StageStatus::Ended) {
        return Err(KairoxError::Session(SessionError::new(
            "public mint stage has already ended; refusing to prepare a live transaction",
        )));
    }

    // Required balance check: the wallet must be able to cover the
    // worst-case total spend this exact plan computed.
    let worst_case_gas_cost = fees.worst_case_gas_cost(gas_limit);
    let worst_case_total = worst_case_total_spend(mint_value, worst_case_gas_cost);
    if balance < worst_case_total {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::InsufficientBalance,
            format!(
                "wallet balance {balance} wei is insufficient for worst-case total spend {worst_case_total} wei"
            ),
        )));
    }

    Ok(PreparedUnsignedPlan {
        chain: request.chain.clone(),
        wallet: request.wallet,
        nonce,
        seadrop_contract: request.seadrop_contract,
        mint_value,
        calldata,
        quantity: request.quantity,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        stage_start: plan.stage_start,
        worst_case_total_spend: worst_case_total,
    })
}

/// Sign an already-validated [`PreparedUnsignedPlan`] and serialize it into
/// a broadcast-ready [`PreparedTransaction`]. The only step in the live
/// pipeline that touches the private key — callers that need to check an
/// aggregate invariant across multiple wallets (e.g. a multi-wallet session
/// spend cap) must do so against [`PreparedUnsignedPlan::worst_case_total_spend`]
/// before calling this, never after.
pub fn finalize_signed_transaction(
    signer: &dyn Signer,
    plan: PreparedUnsignedPlan,
) -> Result<PreparedTransaction, KairoxError> {
    let unsigned = UnsignedEip1559Tx {
        chain_id: plan.chain.chain_id,
        nonce: plan.nonce,
        max_priority_fee_per_gas: plan.max_priority_fee_per_gas,
        max_fee_per_gas: plan.max_fee_per_gas,
        gas_limit: plan.gas_limit,
        to: plan.seadrop_contract,
        value: plan.mint_value,
        data: plan.calldata.clone(),
        access_list: Vec::new(),
    };
    let signing_hash = unsigned.signing_hash();

    let signed = signer
        .sign_transaction(unsigned)
        .map_err(KairoxError::Signing)?;
    let raw_signed_bytes = signed.raw_bytes();
    let tx_hash = signed.tx_hash();

    // Everything the T=0 hot path will ever touch is built here, once,
    // before the stage-open wait: hex-encode the raw signed transaction and
    // serialize the complete eth_sendRawTransaction JSON-RPC request body.
    // `broadcast_to_all` later sends `broadcast.json_rpc_body` verbatim to
    // every send-capable endpoint — no re-encoding, no re-serialization.
    let broadcast_prepare_started = std::time::Instant::now();
    let broadcast = PreparedBroadcast::build(tx_hash, raw_signed_bytes.clone());
    let broadcast_prepare_ms = broadcast_prepare_started.elapsed().as_millis() as u64;

    Ok(PreparedTransaction {
        chain_id: plan.chain.chain_id,
        wallet: plan.wallet,
        nonce: plan.nonce,
        target: plan.seadrop_contract,
        value: plan.mint_value,
        calldata_hash: keccak256(&plan.calldata),
        quantity: plan.quantity,
        gas_limit: plan.gas_limit,
        max_fee_per_gas: plan.max_fee_per_gas,
        max_priority_fee_per_gas: plan.max_priority_fee_per_gas,
        stage_start: plan.stage_start,
        signing_hash,
        raw_signed_bytes,
        tx_hash,
        broadcast,
        broadcast_prepare_ms,
        prepared_at: OffsetDateTime::now_utc(),
    })
}

/// Gather fresh live state, validate every Phase-2 safety invariant, sign,
/// and serialize — producing a [`PreparedTransaction`]. Fails closed (no
/// broadcast-eligible output) on any missing or invalid required input.
/// Equivalent to [`gather_unsigned_plan`] immediately followed by
/// [`finalize_signed_transaction`] — kept as a single call for the
/// single-wallet path, which has no aggregate invariant to check between
/// the two steps.
pub async fn prepare_live_transaction(
    client: &RpcClient,
    signer: &dyn Signer,
    request: &LiveMintRequest,
) -> Result<PreparedTransaction, KairoxError> {
    let plan = gather_unsigned_plan(client, signer.address(), request).await?;
    finalize_signed_transaction(signer, plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use crate::chain::registry::ChainRegistry;
    use crate::signing::signer::LocalSigner;
    use alloy_primitives::address;
    use alloy_sol_types::SolCall;
    use serde_json::json;
    use time::macros::datetime;

    const NFT: Address = address!("000000000000000000000000000000000000c0de");
    const SEADROP: Address = address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5");

    fn signer() -> LocalSigner {
        LocalSigner::from_bytes(keccak256(b"kairox-phase2-test-key").0).unwrap()
    }

    struct MockOpts {
        nonce_hex: &'static str,
        base_fee_hex: &'static str,
        priority_fee_hex: &'static str,
        balance_hex: &'static str,
        estimate_gas: Result<&'static str, (i64, &'static str)>,
        max_total_mintable_by_wallet: u16,
        minter_num_minted: u64,
        current_total_supply: u64,
        max_supply: u64,
        start_time: i64,
        end_time: i64,
    }

    impl Default for MockOpts {
        fn default() -> Self {
            Self {
                nonce_hex: "0x1",
                base_fee_hex: "0x3b9aca00",       // 1 gwei
                priority_fee_hex: "0x3b9aca00",   // 1 gwei
                balance_hex: "0xde0b6b3a7640000", // 1 ETH
                estimate_gas: Ok("0x2bf20"),      // 180000
                max_total_mintable_by_wallet: 5,
                minter_num_minted: 0,
                current_total_supply: 0,
                max_supply: 1_000,
                start_time: datetime!(2020-01-01 00:00:00 UTC).unix_timestamp(),
                end_time: datetime!(2999-01-01 00:00:00 UTC).unix_timestamp(),
            }
        }
    }

    fn build_transport(opts: MockOpts) -> MockTransport {
        let public_drop = seadrop::PublicDropAbi {
            mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
            startTime: alloy_primitives::Uint::from(opts.start_time as u64),
            endTime: alloy_primitives::Uint::from(opts.end_time as u64),
            maxTotalMintableByWallet: opts.max_total_mintable_by_wallet,
            feeBps: 0,
            restrictFeeRecipients: false,
        };
        let public_drop_hex = format!(
            "0x{}",
            hex::encode(seadrop::getPublicDropCall::abi_encode_returns(&public_drop))
        );
        let allowed_hex = format!(
            "0x{}",
            hex::encode(seadrop::getAllowedFeeRecipientsCall::abi_encode_returns(
                &Vec::<Address>::new()
            ))
        );
        let mint_stats_hex = format!(
            "0x{}",
            hex::encode(seadrop::getMintStatsCall::abi_encode_returns(
                &seadrop::getMintStatsReturn {
                    minterNumMinted: U256::from(opts.minter_num_minted),
                    currentTotalSupply: U256::from(opts.current_total_supply),
                    maxSupply: U256::from(opts.max_supply),
                }
            ))
        );

        let mut builder = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond_eth_call_selector(seadrop::getPublicDropCall::SELECTOR, json!(public_drop_hex))
            .respond_eth_call_selector(
                seadrop::getAllowedFeeRecipientsCall::SELECTOR,
                json!(allowed_hex),
            )
            .respond_eth_call_selector(seadrop::getMintStatsCall::SELECTOR, json!(mint_stats_hex))
            .respond(
                "eth_getBlockByNumber",
                json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": opts.base_fee_hex}),
            )
            .respond("eth_maxPriorityFeePerGas", json!(opts.priority_fee_hex))
            .respond("eth_getTransactionCount", json!(opts.nonce_hex))
            .respond("eth_getBalance", json!(opts.balance_hex));

        builder = match opts.estimate_gas {
            Ok(hex_value) => builder.respond("eth_estimateGas", json!(hex_value)),
            Err((code, message)) => builder.error("eth_estimateGas", code, message),
        };

        builder.build()
    }

    async fn connect(opts: MockOpts, role: EndpointRole) -> RpcClient {
        let transport = build_transport(opts);
        RpcClient::connect(Box::new(transport), 1, role, None)
            .await
            .unwrap()
    }

    fn request(wallet: Address) -> LiveMintRequest {
        LiveMintRequest {
            chain: ChainRegistry::builtin().by_id(1).unwrap().clone(),
            nft_contract: NFT,
            seadrop_contract: SEADROP,
            wallet,
            quantity: 1,
            preferred_fee_recipient: None,
            gas_buffer_multiplier: 1.2,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(1_000_000_000_000_000_000u128),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(1_000_000_000_000_000_000u128),
            },
        }
    }

    #[tokio::test]
    async fn parallel_reads_take_the_slowest_call_not_the_sum() {
        // Deterministic, mock-latency-based proof that gather_unsigned_plan's
        // independent reads genuinely run concurrently. The mock's
        // `.delay()` only applies to its method-wide default entry, not to
        // `respond_eth_call_selector`'s routed matches -- so this delays
        // the four non-eth_call reads (block/priority-fee/nonce/balance)
        // and asserts on those; the three eth_call reads run alongside
        // them for free either way. Mirrors
        // opensea_engine::tests::parallel_prepare_reads_take_the_slowest_call_not_the_sum.
        let signer = signer();
        let delay = std::time::Duration::from_millis(80);
        let opts = MockOpts::default();
        let public_drop = seadrop::PublicDropAbi {
            mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
            startTime: alloy_primitives::Uint::from(opts.start_time as u64),
            endTime: alloy_primitives::Uint::from(opts.end_time as u64),
            maxTotalMintableByWallet: opts.max_total_mintable_by_wallet,
            feeBps: 0,
            restrictFeeRecipients: false,
        };
        let public_drop_hex = format!(
            "0x{}",
            hex::encode(seadrop::getPublicDropCall::abi_encode_returns(&public_drop))
        );
        let allowed_hex = format!(
            "0x{}",
            hex::encode(seadrop::getAllowedFeeRecipientsCall::abi_encode_returns(
                &Vec::<Address>::new()
            ))
        );
        let mint_stats_hex = format!(
            "0x{}",
            hex::encode(seadrop::getMintStatsCall::abi_encode_returns(
                &seadrop::getMintStatsReturn {
                    minterNumMinted: U256::ZERO,
                    currentTotalSupply: U256::ZERO,
                    maxSupply: U256::from(1_000u64),
                }
            ))
        );

        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond_eth_call_selector(seadrop::getPublicDropCall::SELECTOR, json!(public_drop_hex))
            .respond_eth_call_selector(
                seadrop::getAllowedFeeRecipientsCall::SELECTOR,
                json!(allowed_hex),
            )
            .respond_eth_call_selector(seadrop::getMintStatsCall::SELECTOR, json!(mint_stats_hex))
            .delay("eth_getBlockByNumber", delay)
            .respond(
                "eth_getBlockByNumber",
                json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": opts.base_fee_hex}),
            )
            .delay("eth_maxPriorityFeePerGas", delay)
            .respond("eth_maxPriorityFeePerGas", json!(opts.priority_fee_hex))
            .delay("eth_getTransactionCount", delay)
            .respond("eth_getTransactionCount", json!(opts.nonce_hex))
            .delay("eth_getBalance", delay)
            .respond("eth_getBalance", json!(opts.balance_hex))
            .respond("eth_estimateGas", json!("0x2bf20"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let req = request(signer.address());

        let started = std::time::Instant::now();
        gather_unsigned_plan(&client, signer.address(), &req)
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert!(
            elapsed < delay * 3,
            "the four delayed reads (block/priority-fee/nonce/balance) run concurrently should \
             take roughly one delay ({delay:?}), not their sum (would be {:?}); took {elapsed:?}",
            delay * 4
        );
    }

    #[tokio::test]
    async fn prepares_and_signs_a_valid_live_transaction() {
        let signer = signer();
        let client = connect(MockOpts::default(), EndpointRole::ReadOnly).await;
        let req = request(signer.address());

        let prepared = prepare_live_transaction(&client, &signer, &req)
            .await
            .unwrap();
        assert_eq!(prepared.nonce, 1);
        assert_eq!(prepared.wallet, signer.address());
        assert!(!prepared.raw_signed_bytes.is_empty());
    }

    /// Regression test: the pure on-chain PUBLIC engine must never
    /// construct (or fabricate) an allow-list mint merely because
    /// something about on-chain state (e.g. a restrictive PublicDrop
    /// config) might suggest a restricted stage. It has no capability to
    /// do so at all -- `gather_unsigned_plan` always encodes exactly
    /// `mintPublic(...)`, regardless of what it reads. Kairox's only
    /// wallet-specific allow-list mint path is the OpenSea engine's
    /// `POST /api/v2/drops/{slug}/mint` response, which supplies the
    /// wallet's actual Merkle proof -- a proof is never derivable from
    /// (or assumed present merely because of) an on-chain Merkle root
    /// alone; see `execution::opensea_validate::verify_allow_list_proof`,
    /// which always uses the proof decoded from that response, never one
    /// invented locally.
    #[tokio::test]
    async fn public_engine_only_ever_encodes_mint_public_never_mint_allow_list() {
        let signer = signer();
        let client = connect(MockOpts::default(), EndpointRole::ReadOnly).await;
        let req = request(signer.address());

        let plan = gather_unsigned_plan(&client, signer.address(), &req)
            .await
            .unwrap();

        let public_selector = seadrop::mintPublicCall::SELECTOR;
        let allow_list_selector = seadrop::mintAllowListCall::SELECTOR;
        assert_eq!(
            &plan.calldata[0..4],
            public_selector,
            "PUBLIC engine calldata must always be mintPublic(...)"
        );
        assert_ne!(
            &plan.calldata[0..4],
            allow_list_selector,
            "PUBLIC engine must never construct mintAllowList(...) calldata -- it has no wallet \
             proof to do so safely, on-chain root or not"
        );
    }

    #[tokio::test]
    async fn rejects_when_signer_does_not_match_requested_wallet() {
        let signer = signer();
        let client = connect(MockOpts::default(), EndpointRole::ReadOnly).await;
        let other_wallet = address!("0000000000000000000000000000000000000fff");
        let req = request(other_wallet);

        let err = prepare_live_transaction(&client, &signer, &req)
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    #[tokio::test]
    async fn nonce_change_between_two_prepares_yields_different_signed_output() {
        let signer = signer();
        let req = request(signer.address());

        let client_a = connect(
            MockOpts {
                nonce_hex: "0x5",
                ..Default::default()
            },
            EndpointRole::ReadOnly,
        )
        .await;
        let prepared_a = prepare_live_transaction(&client_a, &signer, &req)
            .await
            .unwrap();

        let client_b = connect(
            MockOpts {
                nonce_hex: "0x6",
                ..Default::default()
            },
            EndpointRole::ReadOnly,
        )
        .await;
        let prepared_b = prepare_live_transaction(&client_b, &signer, &req)
            .await
            .unwrap();

        assert_eq!(prepared_a.nonce, 5);
        assert_eq!(prepared_b.nonce, 6);
        assert_ne!(prepared_a.tx_hash, prepared_b.tx_hash);
        assert_ne!(prepared_a.raw_signed_bytes, prepared_b.raw_signed_bytes);
    }

    #[tokio::test]
    async fn fee_refresh_changes_prepared_transaction() {
        let signer = signer();
        let req = request(signer.address());

        let client_a = connect(
            MockOpts {
                base_fee_hex: "0x3b9aca00",
                ..Default::default()
            }, // 1 gwei
            EndpointRole::ReadOnly,
        )
        .await;
        let prepared_a = prepare_live_transaction(&client_a, &signer, &req)
            .await
            .unwrap();

        let client_b = connect(
            MockOpts {
                base_fee_hex: "0x77359400",
                ..Default::default()
            }, // 2 gwei
            EndpointRole::ReadOnly,
        )
        .await;
        let prepared_b = prepare_live_transaction(&client_b, &signer, &req)
            .await
            .unwrap();

        assert_ne!(prepared_a.max_fee_per_gas, prepared_b.max_fee_per_gas);
        assert_ne!(prepared_a.tx_hash, prepared_b.tx_hash);
    }

    #[tokio::test]
    async fn gas_estimation_failure_fails_closed_with_no_fallback() {
        let signer = signer();
        let client = connect(
            MockOpts {
                estimate_gas: Err((-32000, "execution reverted")),
                ..Default::default()
            },
            EndpointRole::ReadOnly,
        )
        .await;
        let req = request(signer.address());

        let err = prepare_live_transaction(&client, &signer, &req)
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::Rpc(_)));
    }

    #[tokio::test]
    async fn spend_cap_rejection_prevents_signing() {
        let signer = signer();
        let client = connect(MockOpts::default(), EndpointRole::ReadOnly).await;
        let mut req = request(signer.address());
        req.safety_caps.max_total_spend = U256::from(1u64);

        let err = prepare_live_transaction(&client, &signer, &req)
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::SafetyCap(_)));
    }

    #[tokio::test]
    async fn stage_ended_before_broadcast_fails_closed() {
        let signer = signer();
        let client = connect(
            MockOpts {
                start_time: datetime!(2000-01-01 00:00:00 UTC).unix_timestamp(),
                end_time: datetime!(2000-01-02 00:00:00 UTC).unix_timestamp(),
                ..Default::default()
            },
            EndpointRole::ReadOnly,
        )
        .await;
        let req = request(signer.address());

        let err = prepare_live_transaction(&client, &signer, &req)
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    #[tokio::test]
    async fn sold_out_collection_before_broadcast_fails_closed() {
        let signer = signer();
        let client = connect(
            MockOpts {
                max_supply: 10,
                current_total_supply: 10,
                ..Default::default()
            },
            EndpointRole::ReadOnly,
        )
        .await;
        let req = request(signer.address());

        let err = prepare_live_transaction(&client, &signer, &req)
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::Supply(_)));
    }

    #[tokio::test]
    async fn wallet_allocation_exhausted_before_broadcast_fails_closed() {
        let signer = signer();
        let client = connect(
            MockOpts {
                max_total_mintable_by_wallet: 3,
                minter_num_minted: 3,
                ..Default::default()
            },
            EndpointRole::ReadOnly,
        )
        .await;
        let req = request(signer.address());

        let err = prepare_live_transaction(&client, &signer, &req)
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::Supply(_)));
    }

    #[tokio::test]
    async fn insufficient_balance_fails_closed() {
        let signer = signer();
        let client = connect(
            MockOpts {
                balance_hex: "0x0",
                ..Default::default()
            },
            EndpointRole::ReadOnly,
        )
        .await;
        let req = request(signer.address());

        let err = prepare_live_transaction(&client, &signer, &req)
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }
}
