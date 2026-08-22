//! Top-level orchestration for a live (`--send`) mint: scheduler
//! checkpoints, pre-signing, identical-raw-transaction fan-out, and receipt
//! confirmation. Nothing in this module prints to the console — progress is
//! reported via the `on_progress` callback so the CLI layer owns all
//! output, and heavy work never happens after the final checkpoint besides
//! the broadcast itself.

use std::time::Duration as StdDuration;

use time::OffsetDateTime;

use crate::chain::benchmark::{BenchmarkConfig, HealthPolicy};
use crate::chain::pool::RpcPool;
use crate::domain::timing::SleepSegment;
use crate::protocol::seadrop;
use crate::signing::signer::Signer;

use super::broadcast::{
    BroadcastSummary, EndpointBroadcastResult, broadcast_to_all, summarize_broadcast,
    uncertain_outcome_error,
};
use super::errors::{KairoxError, SessionError, SessionErrorKind};
use super::metrics::{LatencyMetrics, Stopwatch};
use super::prepared::{LiveMintRequest, PreparedTransaction, prepare_live_transaction};
use super::profile::ExecutionProfile;
use super::receipt::{ReceiptState, poll_receipt};
use super::scheduler::{Checkpoint, SchedulerTimings, sleep_until};

#[derive(Debug, Clone, Copy)]
pub struct LiveMintConfig {
    pub scheduler: SchedulerTimings,
    pub receipt_poll_interval: StdDuration,
    pub receipt_timeout: StdDuration,
    /// Reserved for a caller-side full benchmark performed *before*
    /// calling [`run_live_mint`]. No caller does this yet -- `watch` does
    /// not currently have an early, well-before-T0 ranking pass (see
    /// [`BenchmarkConfig::minimal`]'s doc comment for why, and for the
    /// fact that this was previously mis-documented as already existing).
    /// `run_live_mint` itself always benchmarks with
    /// [`BenchmarkConfig::minimal`] internally, regardless of this
    /// field's value. Kept on this struct (rather than removed) so a
    /// future caller building a full profile-derived config for its own
    /// separate early-benchmark call doesn't need a second, parallel
    /// settings type merely to carry this value through.
    pub benchmark: BenchmarkConfig,
    /// Exclusion thresholds applied when selecting read/send endpoints
    /// from benchmark data.
    pub health: HealthPolicy,
    /// Intended lead time of the prewarm/rewarm step ahead of stage-open.
    /// Only has a real temporal effect when `known_stage_start` is set —
    /// see that field's docs.
    pub prewarm_lead: StdDuration,
    /// An authoritative stage-open instant known *before* this pipeline
    /// starts (e.g. off-chain stage timing from an OpenSea drop's
    /// details). When set, rewarm is scheduled as a real
    /// `known_stage_start - prewarm_lead` checkpoint instead of firing
    /// immediately. `None` (the default, and always the case for the pure
    /// on-chain public engine, which only learns stage timing from the
    /// StateCheck checkpoint) preserves Phase 3's original behavior:
    /// rewarm runs immediately, right after benchmarking.
    pub known_stage_start: Option<OffsetDateTime>,
    /// When true, `run_live_mint` runs the entire pipeline (benchmark,
    /// prewarm, scheduler checkpoints, fresh state read, real local
    /// signing/serialization) exactly as normal, then stops immediately
    /// before the broadcast step -- `eth_sendRawTransaction` is never
    /// called. Lets an operator rehearse timing, connection warming, and
    /// preparation against real chain state without any possibility of a
    /// real transaction. Defaults to `false` (a normal live send).
    pub rehearsal: bool,
}

impl Default for LiveMintConfig {
    fn default() -> Self {
        Self {
            scheduler: SchedulerTimings::default(),
            receipt_poll_interval: StdDuration::from_millis(750),
            receipt_timeout: StdDuration::from_secs(60),
            benchmark: BenchmarkConfig::default(),
            health: HealthPolicy::default(),
            prewarm_lead: StdDuration::from_secs(8),
            known_stage_start: None,
            rehearsal: false,
        }
    }
}

impl From<&ExecutionProfile> for LiveMintConfig {
    fn from(profile: &ExecutionProfile) -> Self {
        Self {
            scheduler: profile.scheduler_policy,
            receipt_poll_interval: profile.receipt_poll_interval,
            receipt_timeout: profile.receipt_timeout,
            benchmark: profile.benchmark_policy,
            health: profile.health_policy,
            prewarm_lead: std_duration_from_time(profile.prewarm_lead),
            known_stage_start: None,
            rehearsal: false,
        }
    }
}

fn std_duration_from_time(d: time::Duration) -> StdDuration {
    d.try_into().unwrap_or(StdDuration::ZERO)
}

/// How the prewarm/rewarm step was actually scheduled for one live mint
/// run. Reported honestly rather than silently defaulting — see
/// [`LiveMintConfig::known_stage_start`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrewarmScheduling {
    /// Ran at a real `known_stage_start - prewarm_lead` checkpoint.
    StageRelative,
    /// Ran immediately (right after benchmarking) because no authoritative
    /// stage-start instant was known yet at that point in the pipeline.
    Immediate,
}

/// Progress events emitted during [`run_live_mint`]. Purely informational —
/// the CLI decides how (or whether) to display each one.
#[derive(Debug, Clone)]
pub enum LiveProgress {
    Benchmarking,
    Prewarming { scheduling: PrewarmScheduling },
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
    pub prewarm_scheduling: PrewarmScheduling,
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
    pool: &mut RpcPool,
    signer: &dyn Signer,
    request: &LiveMintRequest,
    config: &LiveMintConfig,
    mut on_progress: impl FnMut(LiveProgress),
) -> Result<LiveMintOutcome, KairoxError> {
    let mut metrics = LatencyMetrics::default();

    // BENCHMARK: exactly one reachability/role-correctness sample per
    // read-capable endpoint -- never the full multi-sample ranking pass
    // (`config.benchmark`, still available to a caller with time to spare
    // before calling this function). An already-live mint has no lead
    // time to hide a multi-second synchronous ranking benchmark in; see
    // `chain::benchmark::BenchmarkConfig::minimal`'s doc comment. Never
    // broadcasts anything, never sends a real transaction merely to
    // measure a send-only endpoint.
    on_progress(LiveProgress::Benchmarking);
    let benchmark_sw = Stopwatch::start();
    pool.benchmark_all(&crate::chain::benchmark::BenchmarkConfig::minimal())
        .await;
    metrics.benchmark_ms = Some(benchmark_sw.elapsed_ms());

    // REWARM (near-T0 prewarm): refresh liveness on every already-connected
    // endpoint right before selection is finalized.
    //
    // When `config.known_stage_start` is set (e.g. the OpenSea engine
    // learned stage timing from off-chain drop details before this
    // pipeline started), `prewarm_lead` gets a real temporal effect: rewarm
    // actually waits for `known_stage_start - prewarm_lead` before running.
    // Never broadcasts anything, never signs, never re-benchmarks — it is
    // purely a wait followed by the same safe liveness probe.
    //
    // When no stage-start is known yet at this point (the pure on-chain
    // public engine only discovers it via the StateCheck checkpoint,
    // later in this function), a real wait can't be computed without
    // adding a redundant preliminary on-chain read purely for scheduling.
    // `prewarm_lead` then has no literal wait to apply, so rewarm instead
    // runs as the very first action after benchmarking and unconditionally
    // -- the same "runs immediately, no wait yet" treatment the
    // StateCheck/Refresh checkpoints already get for the same reason. This
    // fallback is reported honestly via `PrewarmScheduling::Immediate`
    // rather than silently pretending a stage-relative wait happened.
    //
    // `prewarm_ms` records wall-clock elapsed time of the concurrent
    // rewarm call itself, not the wait before it and not a sum of
    // per-endpoint durations. A failed rewarm changes
    // `is_healthy_for_read`/`is_healthy_for_send` immediately (see
    // `EndpointBenchmark::prewarm_status`), so eligibility is always
    // finalized before SELECT runs next -- never after.
    let prewarm_scheduling = if let Some(stage_start) = config.known_stage_start {
        let target = stage_start - config.prewarm_lead;
        let now = OffsetDateTime::now_utc();
        sleep_until(now, target, |segment| {
            on_progress(LiveProgress::Waiting(segment))
        })
        .await;
        PrewarmScheduling::StageRelative
    } else {
        PrewarmScheduling::Immediate
    };
    on_progress(LiveProgress::Prewarming {
        scheduling: prewarm_scheduling,
    });
    let prewarm_sw = Stopwatch::start();
    pool.rewarm_all().await;
    metrics.prewarm_ms = Some(prewarm_sw.elapsed_ms());

    // SELECT: endpoint selection is finalized here, before any checkpoint
    // runs and well before T=0 — nothing after this point re-ranks or
    // re-chooses endpoints.
    let selection_sw = Stopwatch::start();
    let read_client = pool.preferred_read().ok_or_else(|| {
        KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::NoVerifiedReadRpc,
            "no healthy, chain-verified read-capable RPC endpoint available; cannot safely prepare a live transaction",
        ))
    })?;
    let send_clients = pool.select_send_endpoints(&config.health);
    metrics.endpoint_selection_ms = Some(selection_sw.elapsed_ms());
    if send_clients.is_empty() {
        return Err(KairoxError::Session(SessionError::new(
            "no healthy send-capable RPC endpoint available; refusing to prepare a transaction with nowhere to broadcast it",
        )));
    }

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
                        KairoxError::Session(SessionError::new(format!("invalid endTime: {e}")))
                    })?;
                if now >= end {
                    return Err(KairoxError::Session(SessionError::new(
                        "public mint stage has already ended; refusing to schedule a live broadcast",
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
        KairoxError::Session(SessionError::new(
            "scheduler completed without producing a prepared transaction",
        ))
    })?;

    // Never send early: wait for the verified on-chain stage-open instant,
    // even if every checkpoint above already finished ahead of it.
    let now = OffsetDateTime::now_utc();
    sleep_until(now, prepared.stage_start, |segment| {
        on_progress(LiveProgress::Waiting(segment))
    })
    .await;

    // SCHEDULER ACCURACY: how far the actual dispatch instant landed from
    // the verified stage-open target. Positive = late, negative = would
    // have been early (never allowed to actually happen — the sleep above
    // guarantees `actual_dispatch_at >= prepared.stage_start`).
    let actual_dispatch_at = OffsetDateTime::now_utc();
    metrics.scheduler_error_ms =
        Some((actual_dispatch_at - prepared.stage_start).whole_milliseconds() as i64);

    metrics.broadcast_prepare_ms = Some(prepared.broadcast_prepare_ms);

    // REHEARSAL: everything above this line -- benchmarking, prewarming,
    // every scheduler checkpoint, the fresh state read, and real local
    // signing/serialization -- already happened exactly as it would for a
    // real send. Stop here, before touching a single network send
    // endpoint. `eth_sendRawTransaction` is never called on this path.
    if config.rehearsal {
        return Ok(LiveMintOutcome {
            prepared,
            broadcast_results: Vec::new(),
            broadcast_summary: BroadcastSummary::NotSent,
            receipt_state: None,
            metrics,
            prewarm_scheduling,
        });
    }

    // send_clients was already finalized during SELECT, above — no
    // re-ranking or re-selection happens here at T=0.
    on_progress(LiveProgress::Broadcasting {
        send_endpoint_count: send_clients.len(),
    });
    // Hot path: dispatch the already-built payload. No hex-encoding, JSON
    // construction, or serialization happens in `broadcast_to_all` or
    // anything it calls — only the network round trip is timed here.
    let dispatch_sw = Stopwatch::start();
    let broadcast_results = broadcast_to_all(&send_clients, &prepared.broadcast).await;
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
                request.quantity,
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
        // Unreachable here in practice: `summary` above is always built by
        // `summarize_broadcast` from real endpoint results, which never
        // produces `NotSent` -- the rehearsal short-circuit above returns
        // before this line is ever reached. Handled anyway so this match
        // stays exhaustive if that ever changes.
        BroadcastSummary::NotSent => None,
    };

    Ok(LiveMintOutcome {
        prepared,
        broadcast_results,
        broadcast_summary: summary,
        receipt_state,
        metrics,
        prewarm_scheduling,
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
        RpcPool::from_clients(1, healthy_clients(wallet, node_count).await)
    }

    async fn healthy_clients(wallet: Address, node_count: usize) -> Vec<RpcClient> {
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
                .respond("eth_blockNumber", json!("0x1"))
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
        clients
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
            benchmark: crate::chain::benchmark::BenchmarkConfig {
                sample_count: 1,
                sample_delay: StdDuration::ZERO,
            },
            health: crate::chain::benchmark::HealthPolicy::default(),
            prewarm_lead: StdDuration::ZERO,
            known_stage_start: None,
            rehearsal: false,
        }
    }

    #[tokio::test]
    async fn fails_closed_without_send_capable_endpoint() {
        let signer = signer();
        let mut empty_pool = RpcPool::from_clients(1, Vec::new());
        let req = request(signer.address());
        let err = run_live_mint(&mut empty_pool, &signer, &req, &tiny_config(), |_| {})
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    #[tokio::test]
    async fn full_pipeline_broadcasts_identical_bytes_and_confirms_receipt() {
        let signer = signer();
        let mut pool = healthy_pool(signer.address(), 3).await;
        let req = request(signer.address());

        let outcome = run_live_mint(&mut pool, &signer, &req, &tiny_config(), |_| {})
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

    /// A genuine submission-only endpoint: no `eth_chainId` response
    /// configured at all (so it connects as `ConfiguredSendOnly`), but it
    /// does accept `eth_sendRawTransaction` and echoes the real hash.
    /// Returns the client alongside a capture handle so tests can inspect
    /// the exact prebuilt bytes it received.
    async fn submission_only_client(
        role: EndpointRole,
        chain_id: u64,
        label: &str,
    ) -> (RpcClient, crate::chain::mock::CaptureHandle) {
        let transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .echo_raw_transaction_hash()
            .build();
        let capture = transport.capture_handle();
        let client =
            RpcClient::connect(Box::new(transport), chain_id, role, Some(label.to_string()))
                .await
                .unwrap();
        (client, capture)
    }

    #[tokio::test]
    async fn fails_closed_without_any_verified_read_capable_endpoint() {
        let signer = signer();
        let (sequencer, _capture) = submission_only_client(EndpointRole::Sequencer, 1, "seq").await;
        // Send-capable pool, but nothing chain-verified/read-capable in it.
        let mut pool = RpcPool::from_clients(1, vec![sequencer]);
        assert!(!pool.send_capable().is_empty());

        let req = request(signer.address());
        let err = run_live_mint(&mut pool, &signer, &req, &tiny_config(), |_| {})
            .await
            .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    #[tokio::test]
    async fn identical_raw_bytes_reach_a_genuine_submission_only_endpoint_too() {
        let signer = signer();
        // One fully verified read+send node (state comes only from here).
        let mut pool_clients = healthy_clients(signer.address(), 1).await;
        // One genuine submission-only sequencer: no eth_chainId support.
        let (sequencer_client, sequencer_capture) =
            submission_only_client(EndpointRole::Sequencer, 1, "robinhood-sequencer").await;
        pool_clients.push(sequencer_client);

        let mut pool = RpcPool::from_clients(1, pool_clients);
        assert_eq!(pool.read_capable().len(), 1);
        assert_eq!(pool.send_capable().len(), 2);

        let req = request(signer.address());
        let outcome = run_live_mint(&mut pool, &signer, &req, &tiny_config(), |_| {})
            .await
            .unwrap();

        assert_eq!(outcome.broadcast_results.len(), 2);
        assert_eq!(
            sequencer_capture.prebuilt_bodies(),
            vec![outcome.prepared.broadcast.json_rpc_body.clone()],
            "the ConfiguredSendOnly sequencer must receive the exact same prebuilt payload as every other endpoint"
        );
        let expected_hash = outcome.prepared.tx_hash;
        for r in &outcome.broadcast_results {
            assert_eq!(
                r.outcome,
                crate::execution::broadcast::BroadcastOutcome::Accepted {
                    tx_hash: expected_hash
                },
                "every endpoint — including the submission-only one — must see the identical raw tx"
            );
        }
    }

    #[tokio::test]
    async fn rewarm_never_sends_a_dummy_transaction_to_a_submission_only_endpoint() {
        let signer = signer();
        let mut pool_clients = healthy_clients(signer.address(), 1).await;
        let (sequencer_client, sequencer_capture) =
            submission_only_client(EndpointRole::Sequencer, 1, "robinhood-sequencer").await;
        pool_clients.push(sequencer_client);
        let mut pool = RpcPool::from_clients(1, pool_clients);

        let req = request(signer.address());
        let outcome = run_live_mint(&mut pool, &signer, &req, &tiny_config(), |_| {})
            .await
            .unwrap();

        // The submission-only endpoint must see exactly one
        // `eth_sendRawTransaction` call -- the real, prebuilt broadcast at
        // T=0 -- and nothing extra from the prewarm step trying to fake a
        // liveness check on it.
        assert_eq!(
            sequencer_capture.prebuilt_bodies().len(),
            1,
            "rewarm must never send a dummy/fake transaction to a genuine submission-only endpoint"
        );
        let _ = outcome;
    }

    #[tokio::test]
    async fn prewarm_reports_immediate_when_no_stage_start_is_known() {
        let signer = signer();
        let mut pool = healthy_pool(signer.address(), 1).await;
        let req = request(signer.address());

        let outcome = run_live_mint(&mut pool, &signer, &req, &tiny_config(), |_| {})
            .await
            .unwrap();

        assert_eq!(outcome.prewarm_scheduling, PrewarmScheduling::Immediate);
    }

    #[tokio::test]
    async fn prewarm_actually_waits_for_a_real_stage_relative_checkpoint_when_stage_start_is_known()
    {
        let signer = signer();
        let mut pool = healthy_pool(signer.address(), 1).await;
        let req = request(signer.address());

        let mut config = tiny_config();
        let target = OffsetDateTime::now_utc() + time::Duration::milliseconds(80);
        config.known_stage_start = Some(target);
        config.prewarm_lead = StdDuration::ZERO;

        let started = std::time::Instant::now();
        let outcome = run_live_mint(&mut pool, &signer, &req, &config, |_| {})
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(outcome.prewarm_scheduling, PrewarmScheduling::StageRelative);
        assert!(
            elapsed >= std::time::Duration::from_millis(60),
            "a stage-relative prewarm checkpoint must actually wait, not just record a number (elapsed={elapsed:?})"
        );
    }

    #[tokio::test]
    async fn metrics_are_populated_for_benchmark_selection_and_scheduler_accuracy() {
        let signer = signer();
        let mut pool = healthy_pool(signer.address(), 1).await;
        let req = request(signer.address());

        let outcome = run_live_mint(&mut pool, &signer, &req, &tiny_config(), |_| {})
            .await
            .unwrap();

        assert!(outcome.metrics.benchmark_ms.is_some());
        assert!(
            outcome.metrics.prewarm_ms.is_some(),
            "prewarm_ms must be actually populated by a real rewarm step, not left dead"
        );
        assert!(outcome.metrics.endpoint_selection_ms.is_some());
        assert!(outcome.metrics.broadcast_prepare_ms.is_some());
        assert!(outcome.metrics.dispatch_ms.is_some());
        let scheduler_error = outcome
            .metrics
            .scheduler_error_ms
            .expect("scheduler_error_ms must be recorded");
        assert!(
            scheduler_error >= 0,
            "must never dispatch before the verified stage-open instant (scheduler_error_ms={scheduler_error})"
        );
    }

    #[tokio::test]
    async fn benchmarking_never_dispatches_a_broadcast() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .build();
        let capture = transport.capture_handle();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();

        let mut pool = RpcPool::from_clients(1, vec![client]);
        pool.benchmark_all(&crate::chain::benchmark::BenchmarkConfig {
            sample_count: 3,
            sample_delay: StdDuration::ZERO,
        })
        .await;

        assert!(capture.calls_for("eth_sendRawTransaction").is_empty());
        assert!(capture.prebuilt_bodies().is_empty());
        assert!(!capture.calls_for("eth_blockNumber").is_empty());
    }
}
