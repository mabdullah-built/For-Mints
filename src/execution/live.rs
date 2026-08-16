//! Top-level orchestration for a live (`--send`) mint: scheduler
//! checkpoints, pre-signing, identical-raw-transaction fan-out, and receipt
//! confirmation. Nothing in this module prints to the console — progress is
//! reported via the `on_progress` callback so the CLI layer owns all
//! output, and heavy work never happens after the final checkpoint besides
//! the broadcast itself.

use std::time::Duration as StdDuration;

use time::OffsetDateTime;

use crate::chain::pool::RpcPool;
use crate::domain::timing::SleepSegment;
use crate::protocol::seadrop;
use crate::signing::signer::Signer;

use super::broadcast::{
    BroadcastSummary, EndpointBroadcastResult, broadcast_to_all, summarize_broadcast,
    uncertain_outcome_error,
};
use super::errors::{KairoxError, SessionError};
use super::metrics::{LatencyMetrics, Stopwatch};
use super::prepared::{LiveMintRequest, PreparedTransaction, prepare_live_transaction};
use super::receipt::{ReceiptState, poll_receipt};
use super::scheduler::{Checkpoint, SchedulerTimings, sleep_until};

#[derive(Debug, Clone, Copy)]
pub struct LiveMintConfig {
    pub scheduler: SchedulerTimings,
    pub receipt_poll_interval: StdDuration,
    pub receipt_timeout: StdDuration,
}

impl Default for LiveMintConfig {
    fn default() -> Self {
        Self {
            scheduler: SchedulerTimings::default(),
            receipt_poll_interval: StdDuration::from_millis(750),
            receipt_timeout: StdDuration::from_secs(60),
        }
    }
}

/// Progress events emitted during [`run_live_mint`]. Purely informational —
/// the CLI decides how (or whether) to display each one.
#[derive(Debug, Clone)]
pub enum LiveProgress {
    Checkpoint(Checkpoint),
    Waiting(SleepSegment),
    Broadcasting { send_endpoint_count: usize },
    ReceiptPending,
}

#[derive(Debug, Clone)]
pub struct LiveMintOutcome {
    pub prepared: PreparedTransaction,
    pub broadcast_results: Vec<EndpointBroadcastResult>,
    pub broadcast_summary: BroadcastSummary,
    pub receipt_state: Option<ReceiptState>,
    pub metrics: LatencyMetrics,
}

/// Run the full live pipeline: state check, refresh, finalize (sign +
/// serialize), wait for stage open, broadcast identical raw bytes to every
/// send-capable endpoint, and — if propagation is confirmed — poll for a
/// receipt.
///
/// Returns `Err` only for conditions that must stop the session outright
/// (no read/send-capable endpoint, required live state unobtainable, or an
/// uncertain broadcast outcome). A clean "nothing was broadcast" result
/// (every endpoint rejected the transaction) is returned as `Ok` with
/// [`BroadcastSummary::AllRejected`] — that is a known, safe outcome, not
/// an ambiguous one.
pub async fn run_live_mint(
    pool: &RpcPool,
    signer: &dyn Signer,
    request: &LiveMintRequest,
    config: &LiveMintConfig,
    mut on_progress: impl FnMut(LiveProgress),
) -> Result<LiveMintOutcome, KairoxError> {
    let read_client = pool.preferred_read().ok_or_else(|| {
        KairoxError::Session(SessionError(
            "no read-capable RPC endpoint available; cannot safely prepare a live transaction"
                .into(),
        ))
    })?;
    if pool.send_capable().is_empty() {
        return Err(KairoxError::Session(SessionError(
            "no send-capable RPC endpoint available; refusing to prepare a transaction with nowhere to broadcast it".into(),
        )));
    }

    let mut metrics = LatencyMetrics::default();
    let mut prepared: Option<PreparedTransaction> = None;

    for (checkpoint, lead) in config.scheduler.checkpoints() {
        // We don't yet know the stage-open instant until the first
        // successful state read, so the very first checkpoint always fires
        // immediately; subsequent checkpoints wait relative to the
        // best-known stage-open time.
        if let Some(p) = &prepared {
            let target = p.stage_start - lead;
            let now = OffsetDateTime::now_utc();
            sleep_until(now, target, |segment| {
                on_progress(LiveProgress::Waiting(segment))
            })
            .await;
        }

        on_progress(LiveProgress::Checkpoint(checkpoint));

        match checkpoint {
            Checkpoint::StateCheck => {
                let sw = Stopwatch::start();
                let calldata = seadrop::encode_get_public_drop(request.nft_contract)?;
                let raw = read_client
                    .eth_call(request.seadrop_contract, &calldata)
                    .await?;
                let public_drop = seadrop::decode_get_public_drop(&raw)?;
                metrics.metadata_ms = Some(sw.elapsed_ms());

                let now = OffsetDateTime::now_utc();
                let end = OffsetDateTime::from_unix_timestamp(public_drop.end_time as i64)
                    .map_err(|e| {
                        KairoxError::Session(SessionError(format!("invalid endTime: {e}")))
                    })?;
                if now >= end {
                    return Err(KairoxError::Session(SessionError(
                        "public mint stage has already ended; refusing to schedule a live broadcast".into(),
                    )));
                }
            }
            Checkpoint::Refresh | Checkpoint::Finalize => {
                let sw = Stopwatch::start();
                let candidate = prepare_live_transaction(read_client, signer, request).await?;
                let elapsed = sw.elapsed_ms();
                if checkpoint == Checkpoint::Refresh {
                    metrics.nonce_ms = Some(elapsed);
                } else {
                    metrics.sign_ms = Some(elapsed);
                    metrics.serialize_ms = Some(0);
                }
                prepared = Some(candidate);
            }
        }
    }

    let prepared = prepared.ok_or_else(|| {
        KairoxError::Session(SessionError(
            "scheduler completed without producing a prepared transaction".into(),
        ))
    })?;

    // Never send early: wait for the verified on-chain stage-open instant,
    // even if every checkpoint above already finished ahead of it.
    let now = OffsetDateTime::now_utc();
    sleep_until(now, prepared.stage_start, |segment| {
        on_progress(LiveProgress::Waiting(segment))
    })
    .await;

    let send_clients = pool.send_capable();
    on_progress(LiveProgress::Broadcasting {
        send_endpoint_count: send_clients.len(),
    });
    let dispatch_sw = Stopwatch::start();
    let broadcast_results =
        broadcast_to_all(&send_clients, &prepared.raw_signed_bytes, prepared.tx_hash).await;
    metrics.dispatch_ms = Some(dispatch_sw.elapsed_ms());
    metrics.rpc_accept_ms = broadcast_results.iter().filter_map(|r| r.latency_ms).min();

    let summary = summarize_broadcast(&broadcast_results);

    let receipt_state = match &summary {
        BroadcastSummary::Confirmed { .. } => {
            on_progress(LiveProgress::ReceiptPending);
            let receipt_sw = Stopwatch::start();
            let state = poll_receipt(
                read_client,
                prepared.tx_hash,
                request.nft_contract,
                request.wallet,
                config.receipt_poll_interval,
                config.receipt_timeout,
                || on_progress(LiveProgress::ReceiptPending),
            )
            .await;
            metrics.receipt_inclusion_ms = Some(receipt_sw.elapsed_ms());
            Some(state)
        }
        BroadcastSummary::AllRejected => None,
        BroadcastSummary::Uncertain => {
            return Err(uncertain_outcome_error(&broadcast_results));
        }
    };

    Ok(LiveMintOutcome {
        prepared,
        broadcast_results,
        broadcast_summary: summary,
        receipt_state,
        metrics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use crate::chain::registry::ChainRegistry;
    use crate::chain::rpc::RpcClient;
    use crate::domain::fees::SafetyCaps;
    use crate::protocol::seadrop::{self as sd, PublicDropAbi};
    use crate::signing::signer::{LocalSigner, Signer};
    use alloy_primitives::{Address, U256, address, keccak256};
    use alloy_sol_types::SolCall;
    use serde_json::{Value, json};
    use time::Duration;
    use time::macros::datetime;

    const NFT: Address = address!("000000000000000000000000000000000000c0de");
    const SEADROP: Address = address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5");

    fn signer() -> LocalSigner {
        LocalSigner::from_bytes(keccak256(b"kairox-phase2-live-test-key").0).unwrap()
    }

    fn tx_hash_topic(addr: Address) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[12..32].copy_from_slice(addr.as_slice());
        t
    }

    async fn healthy_pool(wallet: Address, node_count: usize) -> RpcPool {
        let mut clients = Vec::new();
        for i in 0..node_count {
            let public_drop = PublicDropAbi {
                mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
                startTime: alloy_primitives::Uint::from(
                    datetime!(2020-01-01 00:00:00 UTC).unix_timestamp() as u64,
                ),
                endTime: alloy_primitives::Uint::from(
                    datetime!(2999-01-01 00:00:00 UTC).unix_timestamp() as u64,
                ),
                maxTotalMintableByWallet: 5,
                feeBps: 0,
                restrictFeeRecipients: false,
            };
            let public_drop_hex = format!(
                "0x{}",
                hex::encode(sd::getPublicDropCall::abi_encode_returns(&public_drop))
            );
            let allowed_hex = format!(
                "0x{}",
                hex::encode(sd::getAllowedFeeRecipientsCall::abi_encode_returns(&Vec::<
                    Address,
                >::new(
                )))
            );
            let mint_stats_hex = format!(
                "0x{}",
                hex::encode(sd::getMintStatsCall::abi_encode_returns(
                    &sd::getMintStatsReturn {
                        minterNumMinted: U256::ZERO,
                        currentTotalSupply: U256::from(10u64),
                        maxSupply: U256::from(1_000u64),
                    }
                ))
            );

            let transport = MockTransport::builder()
                .respond("eth_chainId", json!("0x1"))
                .respond_eth_call_selector(sd::getPublicDropCall::SELECTOR, json!(public_drop_hex))
                .respond_eth_call_selector(
                    sd::getAllowedFeeRecipientsCall::SELECTOR,
                    json!(allowed_hex),
                )
                .respond_eth_call_selector(sd::getMintStatsCall::SELECTOR, json!(mint_stats_hex))
                .respond(
                    "eth_getBlockByNumber",
                    json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x3b9aca00"}),
                )
                .respond("eth_maxPriorityFeePerGas", json!("0x3b9aca00"))
                .respond("eth_getTransactionCount", json!("0x0"))
                .respond("eth_getBalance", json!("0xde0b6b3a7640000"))
                .respond("eth_estimateGas", json!("0x2bf20"))
                .echo_raw_transaction_hash()
                .respond_dynamic("eth_getTransactionReceipt", move |params| {
                    let queried_hash = params.get(0).and_then(Value::as_str).unwrap_or("0x").to_string();
                    json!({
                        "transactionHash": queried_hash,
                        "status": "0x1",
                        "blockNumber": "0x1",
                        "logs": [{
                            "address": NFT.to_string(),
                            "topics": [
                                format!("0x{}", hex::encode(keccak256(b"Transfer(address,address,uint256)"))),
                                format!("0x{}", hex::encode([0u8;32])),
                                format!("0x{}", hex::encode(tx_hash_topic(wallet))),
                                format!("0x{}", hex::encode(U256::from(7u64).to_be_bytes::<32>())),
                            ],
                            "data": "0x"
                        }]
                    })
                })
                .build();
            let role = if i == 0 {
                EndpointRole::ReadWrite
            } else {
                EndpointRole::SendOnly
            };
            clients.push(
                RpcClient::connect(Box::new(transport), 1, role, Some(format!("node-{i}")))
                    .await
                    .unwrap(),
            );
        }
        RpcPool::from_clients(1, clients)
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

    fn tiny_config() -> LiveMintConfig {
        LiveMintConfig {
            scheduler: SchedulerTimings {
                state_check_lead: Duration::milliseconds(0),
                refresh_lead: Duration::milliseconds(0),
                finalize_lead: Duration::milliseconds(0),
            },
            receipt_poll_interval: StdDuration::from_millis(5),
            receipt_timeout: StdDuration::from_millis(200),
        }
    }

    #[tokio::test]
    async fn fails_closed_without_send_capable_endpoint() {
        let signer = signer();
        let empty_pool = RpcPool::from_clients(1, Vec::new());
        let req = request(signer.address());
        let err = run_live_mint(&empty_pool, &signer, &req, &tiny_config(), |_| {})
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    #[tokio::test]
    async fn full_pipeline_broadcasts_identical_bytes_and_confirms_receipt() {
        let signer = signer();
        let pool = healthy_pool(signer.address(), 3).await;
        let req = request(signer.address());

        let outcome = run_live_mint(&pool, &signer, &req, &tiny_config(), |_| {})
            .await
            .unwrap();

        assert!(matches!(
            outcome.broadcast_summary,
            BroadcastSummary::Confirmed { .. }
        ));
        assert_eq!(
            outcome.broadcast_results.len(),
            3,
            "all 3 nodes are send-capable (ReadWrite + 2x SendOnly)"
        );
        for r in &outcome.broadcast_results {
            assert!(matches!(
                r.outcome,
                crate::execution::broadcast::BroadcastOutcome::Accepted { .. }
            ));
        }
        assert!(matches!(
            outcome.receipt_state,
            Some(ReceiptState::ConfirmedSuccess { .. })
        ));
    }
}
