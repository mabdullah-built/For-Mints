//! `OpenSeaDropMintEngine` orchestration.
//!
//! Unlike the pure on-chain [`super::live::run_live_mint`], this engine's
//! critical path genuinely depends on an OpenSea API round trip: a
//! wallet-specific transaction can only be requested once the stage is
//! (or is about to become) active, so "T=0 = dispatch prebuilt bytes"
//! does not hold here — see [`OpenSeaMintOutcome::metrics`]'s
//! `api_to_dispatch_ms`, which measures that honestly instead of assuming
//! it away. Everything that *can* be moved out of the critical path (pool
//! benchmarking/rewarming, drop-details/slug resolution, signing-key load)
//! still is.

use std::time::Duration as StdDuration;

use alloy_primitives::{Address, U256, keccak256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::chain::pool::RpcPool;
use crate::chain::registry::ChainInfo;
use crate::chain::rpc::PreparedBroadcast;
use crate::domain::fees::{Eip1559Fees, SafetyCaps, worst_case_total_spend};
use crate::domain::timing::SleepSegment;
use crate::opensea::client::OpenSeaClient;
use crate::opensea::errors::OpenSeaError;
use crate::opensea::models::DropDetailedResponse;
use crate::signing::signer::Signer;
use crate::signing::transaction::UnsignedEip1559Tx;

use super::broadcast::{
    BroadcastSummary, EndpointBroadcastResult, broadcast_to_all, summarize_broadcast,
    uncertain_outcome_error,
};
use super::errors::{KairoxError, SessionError};
use super::live::PrewarmScheduling;
use super::metrics::{LatencyMetrics, Stopwatch};
use super::opensea_validate::{OpenSeaValidationInput, validate_opensea_mint_response};
use super::prepared::PreparedTransaction;
use super::receipt::{ReceiptState, poll_receipt};
use super::scheduler::sleep_until;

/// Everything [`run_opensea_mint`] needs. Analogous to
/// [`super::prepared::LiveMintRequest`], but the target/calldata/value come
/// from OpenSea (then get locally validated) instead of being encoded
/// directly from the known public-mint ABI.
#[derive(Debug, Clone)]
pub struct OpenSeaMintRequest {
    pub chain: ChainInfo,
    pub slug: String,
    pub nft_contract: Address,
    pub seadrop_contract: Address,
    pub wallet: Address,
    pub quantity: u64,
    pub gas_buffer_multiplier: f64,
    pub safety_caps: SafetyCaps,
    pub receipt_poll_interval: StdDuration,
    pub receipt_timeout: StdDuration,
    pub benchmark: crate::chain::benchmark::BenchmarkConfig,
    pub health: crate::chain::benchmark::HealthPolicy,
    pub prewarm_lead: StdDuration,
}

/// Progress events emitted during [`run_opensea_mint`]. Mirrors
/// [`super::live::LiveProgress`]'s shape/philosophy: purely informational,
/// nothing here prints to the console.
#[derive(Debug, Clone)]
pub enum OpenSeaProgress {
    Benchmarking,
    FetchingDropDetails,
    Prewarming { scheduling: PrewarmScheduling },
    Waiting(SleepSegment),
    RequestingMintTransaction,
    Validating,
    Simulating,
    Broadcasting { send_endpoint_count: usize },
    ReceiptPending,
}

#[derive(Debug, Clone)]
pub struct OpenSeaMintOutcome {
    pub prepared: PreparedTransaction,
    pub broadcast_results: Vec<EndpointBroadcastResult>,
    pub broadcast_summary: BroadcastSummary,
    pub receipt_state: Option<ReceiptState>,
    pub metrics: LatencyMetrics,
    /// The raw drop details OpenSea reported — off-chain metadata, kept
    /// separate from (and never treated as stronger than) the on-chain
    /// state actually used to validate/simulate the transaction.
    pub drop_details: DropDetailedResponse,
}

/// Run the full OpenSea-drop live pipeline: benchmark/prewarm the RPC
/// pool, fetch drop details, wait for stage-open if a stage start is
/// known, request the wallet-specific mint transaction (bounded retry),
/// validate it locally (untrusted input — see `opensea_validate`),
/// revalidate/simulate on-chain, sign once, fan out the identical raw
/// bytes to every send-capable endpoint, and poll for a receipt.
pub async fn run_opensea_mint(
    opensea: &OpenSeaClient,
    pool: &mut RpcPool,
    signer: &dyn Signer,
    request: &OpenSeaMintRequest,
    mut on_progress: impl FnMut(OpenSeaProgress),
) -> Result<OpenSeaMintOutcome, KairoxError> {
    if signer.address() != request.wallet {
        return Err(KairoxError::Session(SessionError(format!(
            "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
            signer.address(),
            request.wallet
        ))));
    }

    let mut metrics = LatencyMetrics::default();

    // BENCHMARK — identical role to the public engine's.
    on_progress(OpenSeaProgress::Benchmarking);
    let sw = Stopwatch::start();
    pool.benchmark_all(&request.benchmark).await;
    metrics.benchmark_ms = Some(sw.elapsed_ms());

    // PRE-STAGE OPENSEA PREPARATION: fetching drop details is both how
    // Kairox learns stage timing/price *and* (since it reuses the same
    // `reqwest::Client`) how the OpenSea HTTPS connection gets warmed —
    // deliberately not a second, separate warm-up request, since Kairox
    // must never hammer the API with speculative calls.
    on_progress(OpenSeaProgress::FetchingDropDetails);
    let sw = Stopwatch::start();
    let drop_details = opensea.get_drop_details(&request.slug).await?;
    let drop_details_ms = sw.elapsed_ms();
    metrics.opensea_drop_details_ms = Some(drop_details_ms);
    metrics.opensea_prewarm_ms = Some(drop_details_ms);

    let stage = drop_details
        .active_stage
        .as_ref()
        .or(drop_details.next_stage.as_ref());
    let known_stage_start = stage.and_then(|s| OffsetDateTime::parse(&s.start_time, &Rfc3339).ok());
    let expected_price_per_token = stage
        .and_then(|s| s.price.as_ref())
        .and_then(|p| U256::from_str_radix(p, 10).ok());

    // REWARM: real stage-relative checkpoint when drop details gave us an
    // authoritative stage start (see `LiveMintConfig::known_stage_start`'s
    // docs for why this differs from the public engine, which can't know
    // stage_start this early).
    let prewarm_scheduling = if let Some(stage_start) = known_stage_start {
        let target = stage_start - request.prewarm_lead;
        let now = OffsetDateTime::now_utc();
        sleep_until(now, target, |segment| {
            on_progress(OpenSeaProgress::Waiting(segment))
        })
        .await;
        PrewarmScheduling::StageRelative
    } else {
        PrewarmScheduling::Immediate
    };
    on_progress(OpenSeaProgress::Prewarming {
        scheduling: prewarm_scheduling,
    });
    let sw = Stopwatch::start();
    pool.rewarm_all().await;
    metrics.prewarm_ms = Some(sw.elapsed_ms());

    // SELECT — same deterministic selection as the public engine, and
    // finalized before the OpenSea-dependent critical path below.
    let selection_sw = Stopwatch::start();
    let read_client = pool.preferred_read().ok_or_else(|| {
        KairoxError::Session(SessionError(
            "no healthy, chain-verified read-capable RPC endpoint available; cannot safely validate or simulate an OpenSea-provided transaction"
                .into(),
        ))
    })?;
    let send_clients = pool.select_send_endpoints(&request.health);
    metrics.endpoint_selection_ms = Some(selection_sw.elapsed_ms());
    if send_clients.is_empty() {
        return Err(KairoxError::Session(SessionError(
            "no healthy send-capable RPC endpoint available; refusing to prepare a transaction with nowhere to broadcast it".into(),
        )));
    }

    // Never request/broadcast before the stage is actually open, even if
    // every step above finished ahead of the known stage-start instant.
    if let Some(stage_start) = known_stage_start {
        let now = OffsetDateTime::now_utc();
        sleep_until(now, stage_start, |segment| {
            on_progress(OpenSeaProgress::Waiting(segment))
        })
        .await;
    }

    // CRITICAL PATH START — everything from here to DISPATCH is the
    // OpenSea-dependent part measured by `api_to_dispatch_ms`.
    let api_to_dispatch_sw = Stopwatch::start();

    on_progress(OpenSeaProgress::RequestingMintTransaction);
    let sw = Stopwatch::start();
    let quantity_u32 = u32::try_from(request.quantity).map_err(|_| {
        KairoxError::Session(SessionError(format!(
            "quantity {} does not fit the OpenSea mint API's u32 range",
            request.quantity
        )))
    })?;
    let (mint_response, retry_count) =
        request_mint_with_bounded_retry(opensea, &request.slug, request.wallet, quantity_u32)
            .await?;
    metrics.opensea_mint_request_ms = Some(sw.elapsed_ms());
    metrics.opensea_retry_count = Some(retry_count);

    // VALIDATE — the response is untrusted external input until this
    // passes. See `opensea_validate` module docs.
    on_progress(OpenSeaProgress::Validating);
    let sw = Stopwatch::start();
    let validation_input = OpenSeaValidationInput {
        chain_id: request.chain.chain_id,
        expected_seadrop_contract: request.seadrop_contract,
        expected_collection: request.nft_contract,
        expected_wallet: request.wallet,
        expected_quantity: request.quantity,
        safety_caps: request.safety_caps,
        expected_price_per_token,
    };
    let validated = validate_opensea_mint_response(&mint_response, &validation_input)?;
    metrics.opensea_validation_ms = Some(sw.elapsed_ms());

    // ON-CHAIN REVALIDATION: only a verified read-capable endpoint is ever
    // used for state/simulation -- never SEND_ONLY/SEQUENCER/
    // ConfiguredSendOnly (those are excluded from `preferred_read` itself,
    // see `chain::pool`).
    let prepare_sw = Stopwatch::start();
    on_progress(OpenSeaProgress::Simulating);
    let sim_sw = Stopwatch::start();
    let gas_estimate = read_client
        .estimate_gas(
            request.wallet,
            validated.target,
            &validated.calldata,
            validated.value,
        )
        .await
        .map_err(|e| {
            KairoxError::OpenSea(OpenSeaError::SimulationFailure {
                detail: e.to_string(),
            })
        })?;
    metrics.signed_engine_simulation_ms = Some(sim_sw.elapsed_ms());
    let gas_limit = ((gas_estimate as f64) * request.gas_buffer_multiplier.max(1.0)).ceil() as u64;

    let block = read_client.latest_block().await?;
    let base_fee_per_gas = block.base_fee_per_gas.ok_or_else(|| {
        KairoxError::Session(SessionError(
            "chain does not report an EIP-1559 baseFeePerGas; cannot safely price a live transaction"
                .into(),
        ))
    })?;
    let max_priority_fee_per_gas = read_client.max_priority_fee_per_gas().await?;
    let max_fee_per_gas = base_fee_per_gas
        .saturating_mul(2)
        .saturating_add(max_priority_fee_per_gas);
    let fees = Eip1559Fees::new(base_fee_per_gas, max_priority_fee_per_gas, max_fee_per_gas)?;

    let nonce = read_client.transaction_count(request.wallet).await?;
    let balance = read_client.get_balance(request.wallet).await?;

    let worst_case_gas_cost = fees.worst_case_gas_cost(gas_limit);
    let worst_case_total = worst_case_total_spend(validated.value, worst_case_gas_cost);
    request
        .safety_caps
        .check(validated.value, worst_case_gas_cost, worst_case_total)?;
    if balance < worst_case_total {
        return Err(KairoxError::Session(SessionError(format!(
            "wallet balance {balance} wei is insufficient for worst-case total spend {worst_case_total} wei"
        ))));
    }

    let unsigned = UnsignedEip1559Tx {
        chain_id: request.chain.chain_id,
        nonce,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        max_fee_per_gas: fees.max_fee_per_gas(),
        gas_limit,
        to: validated.target,
        value: validated.value,
        data: validated.calldata.clone(),
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
    metrics.broadcast_prepare_ms = Some(broadcast_prepare_ms);
    metrics.signed_engine_prepare_ms = Some(prepare_sw.elapsed_ms());

    let prepared = PreparedTransaction {
        chain_id: request.chain.chain_id,
        wallet: request.wallet,
        nonce,
        target: validated.target,
        value: validated.value,
        calldata_hash: keccak256(&validated.calldata),
        quantity: request.quantity,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        stage_start: known_stage_start.unwrap_or_else(OffsetDateTime::now_utc),
        signing_hash,
        raw_signed_bytes,
        tx_hash,
        broadcast,
        broadcast_prepare_ms,
        prepared_at: OffsetDateTime::now_utc(),
    };

    // DISPATCH — identical raw bytes fanned out to every selected
    // send-capable endpoint, exactly like the public engine.
    on_progress(OpenSeaProgress::Broadcasting {
        send_endpoint_count: send_clients.len(),
    });
    let dispatch_sw = Stopwatch::start();
    let broadcast_results = broadcast_to_all(&send_clients, &prepared.broadcast).await;
    metrics.dispatch_ms = Some(dispatch_sw.elapsed_ms());
    metrics.api_to_dispatch_ms = Some(api_to_dispatch_sw.elapsed_ms());

    let summary = summarize_broadcast(&broadcast_results);
    if let BroadcastSummary::Uncertain = summary {
        // Possible-send uncertainty after signing is never confused with
        // pre-signing API retry policy -- always MustStopSession, exactly
        // like the public engine.
        return Err(uncertain_outcome_error(&broadcast_results));
    }

    let receipt_state = if let BroadcastSummary::Confirmed { tx_hash } = summary {
        let receipt_sw = Stopwatch::start();
        let state = poll_receipt(
            read_client,
            tx_hash,
            request.nft_contract,
            request.wallet,
            request.receipt_poll_interval,
            request.receipt_timeout,
            || on_progress(OpenSeaProgress::ReceiptPending),
        )
        .await;
        metrics.receipt_inclusion_ms = Some(receipt_sw.elapsed_ms());
        Some(state)
    } else {
        None
    };

    Ok(OpenSeaMintOutcome {
        prepared,
        broadcast_results,
        broadcast_summary: summary,
        receipt_state,
        metrics,
        drop_details,
    })
}

/// Bounded, conservative retry for the mint-transaction request only —
/// never for anything after signing. Retries only transport-level/server
/// uncertainty (timeout before any response, 5xx, 429); every
/// eligibility/allocation/supply/auth/malformed-request outcome is
/// terminal and never retried, so repeated calls can never be used to
/// evade an allocation.
async fn request_mint_with_bounded_retry(
    client: &OpenSeaClient,
    slug: &str,
    wallet: Address,
    quantity: u32,
) -> Result<(crate::opensea::models::DropMintResponse, u32), OpenSeaError> {
    const MAX_ATTEMPTS: u32 = 3;
    const RETRY_DELAY: StdDuration = StdDuration::from_millis(300);

    let mut last_err = None;
    for attempt in 0..MAX_ATTEMPTS {
        match client
            .request_mint_transaction(slug, wallet, quantity)
            .await
        {
            Ok(response) => return Ok((response, attempt)),
            Err(e) if is_retryable_before_signing(&e) => {
                last_err = Some(e);
                if attempt + 1 < MAX_ATTEMPTS {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.expect("loop always sets last_err before exhausting MAX_ATTEMPTS"))
}

fn is_retryable_before_signing(err: &OpenSeaError) -> bool {
    matches!(
        err,
        OpenSeaError::ApiTimeout
            | OpenSeaError::ApiUnavailable { .. }
            | OpenSeaError::ServerError { .. }
            | OpenSeaError::RateLimited
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use crate::chain::registry::ChainRegistry;
    use crate::chain::rpc::RpcClient;
    use crate::domain::fees::SafetyCaps;
    use crate::execution::receipt::ReceiptState;
    use crate::opensea::mock::MockOpenSeaTransport;
    use crate::protocol::seadrop;
    use crate::signing::signer::LocalSigner;
    use alloy_primitives::address;
    use serde_json::{Value, json};

    const NFT: Address = address!("000000000000000000000000000000000000c0de");
    const SEADROP: Address = address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5");

    fn signer() -> LocalSigner {
        LocalSigner::from_bytes(keccak256(b"kairox-phase4-opensea-test-key").0).unwrap()
    }

    fn tx_hash_topic(addr: Address) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[12..32].copy_from_slice(addr.as_slice());
        t
    }

    async fn healthy_chain_client(wallet: Address, role: EndpointRole, label: &str) -> RpcClient {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .respond("eth_estimateGas", json!("0x2bf20"))
            .respond(
                "eth_getBlockByNumber",
                json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x3b9aca00"}),
            )
            .respond("eth_maxPriorityFeePerGas", json!("0x3b9aca00"))
            .respond("eth_getTransactionCount", json!("0x0"))
            .respond("eth_getBalance", json!("0xde0b6b3a7640000"))
            .echo_raw_transaction_hash()
            .respond_dynamic("eth_getTransactionReceipt", move |params| {
                let queried_hash = params
                    .get(0)
                    .and_then(Value::as_str)
                    .unwrap_or("0x")
                    .to_string();
                json!({
                    "transactionHash": queried_hash,
                    "status": "0x1",
                    "blockNumber": "0x1",
                    "logs": [{
                        "address": NFT.to_string(),
                        "topics": [
                            format!("0x{}", hex::encode(keccak256(b"Transfer(address,address,uint256)"))),
                            format!("0x{}", hex::encode([0u8; 32])),
                            format!("0x{}", hex::encode(tx_hash_topic(wallet))),
                            format!("0x{}", hex::encode(U256::from(7u64).to_be_bytes::<32>())),
                        ],
                        "data": "0x"
                    }]
                })
            })
            .build();
        RpcClient::connect(Box::new(transport), 1, role, Some(label.to_string()))
            .await
            .unwrap()
    }

    fn drop_details_response() -> Value {
        json!({
            "collection_slug": "cool-cats",
            "chain": "ethereum",
            "contract_address": NFT.to_string(),
            "drop_type": "seadrop_v1_erc721",
            "is_minting": true,
            "stages": [],
        })
    }

    fn valid_mint_response_json(quantity: u64, value_wei: u128) -> Value {
        let calldata = seadrop::encode_mint_public(
            NFT,
            address!("0000000000000000000000000000000000fee000"),
            Address::ZERO,
            quantity,
        )
        .unwrap();
        json!({
            "to": SEADROP.to_string(),
            "data": format!("0x{}", hex::encode(&calldata)),
            "value": format!("0x{value_wei:x}"),
            "chain": "ethereum",
        })
    }

    fn request(wallet: Address) -> OpenSeaMintRequest {
        OpenSeaMintRequest {
            chain: ChainRegistry::builtin().by_id(1).unwrap().clone(),
            slug: "cool-cats".into(),
            nft_contract: NFT,
            seadrop_contract: SEADROP,
            wallet,
            quantity: 1,
            gas_buffer_multiplier: 1.2,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(1_000_000_000_000_000_000u128),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(1_000_000_000_000_000_000u128),
            },
            receipt_poll_interval: StdDuration::from_millis(5),
            receipt_timeout: StdDuration::from_millis(200),
            benchmark: crate::chain::benchmark::BenchmarkConfig {
                sample_count: 1,
                sample_delay: StdDuration::ZERO,
            },
            health: crate::chain::benchmark::HealthPolicy::default(),
            prewarm_lead: StdDuration::ZERO,
        }
    }

    #[tokio::test]
    async fn full_pipeline_validates_signs_dispatches_and_confirms_receipt() {
        let signer = signer();
        let client =
            healthy_chain_client(signer.address(), EndpointRole::ReadWrite, "node-0").await;
        let mut pool = RpcPool::from_clients(1, vec![client]);

        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                200,
                valid_mint_response_json(1, 0),
            )
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let req = request(signer.address());

        let outcome = run_opensea_mint(&opensea, &mut pool, &signer, &req, |_| {})
            .await
            .unwrap();

        assert_eq!(outcome.broadcast_results.len(), 1);
        match outcome.receipt_state {
            Some(ReceiptState::ConfirmedSuccess { .. }) => {}
            other => panic!("expected ConfirmedSuccess, got {other:?}"),
        }
        assert!(
            outcome.metrics.api_to_dispatch_ms.is_some(),
            "the OpenSea-dependent critical path must be honestly measured"
        );
        assert_eq!(outcome.metrics.opensea_retry_count, Some(0));
    }

    #[tokio::test]
    async fn identical_raw_bytes_reach_a_genuine_submission_only_endpoint_too() {
        let signer = signer();
        let read_client =
            healthy_chain_client(signer.address(), EndpointRole::ReadWrite, "node-0").await;

        let sequencer_transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .echo_raw_transaction_hash()
            .build();
        let sequencer_capture = sequencer_transport.capture_handle();
        let sequencer_client = RpcClient::connect(
            Box::new(sequencer_transport),
            1,
            EndpointRole::Sequencer,
            Some("sequencer".into()),
        )
        .await
        .unwrap();

        let mut pool = RpcPool::from_clients(1, vec![read_client, sequencer_client]);
        assert_eq!(pool.send_capable().len(), 2);

        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                200,
                valid_mint_response_json(1, 0),
            )
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let req = request(signer.address());

        let outcome = run_opensea_mint(&opensea, &mut pool, &signer, &req, |_| {})
            .await
            .unwrap();

        assert_eq!(outcome.broadcast_results.len(), 2);
        assert_eq!(
            sequencer_capture.prebuilt_bodies(),
            vec![outcome.prepared.broadcast.json_rpc_body.clone()],
            "the submission-only endpoint must receive the exact same prebuilt payload as every other endpoint"
        );
    }

    #[tokio::test]
    async fn quantity_mismatch_from_opensea_is_rejected_before_any_signing() {
        let signer = signer();
        let client =
            healthy_chain_client(signer.address(), EndpointRole::ReadWrite, "node-0").await;
        let mut pool = RpcPool::from_clients(1, vec![client]);

        // OpenSea returns calldata for quantity=5 while the request asked
        // for 1 -- must fail closed, never sign a mismatched quantity.
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                200,
                valid_mint_response_json(5, 0),
            )
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let req = request(signer.address());

        let err = run_opensea_mint(&opensea, &mut pool, &signer, &req, |_| {})
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::QuantityMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn uncertain_broadcast_outcome_is_must_stop_session() {
        use crate::execution::errors::{Categorize, ErrorCategory};

        let signer = signer();
        // Read-only: contributes state/simulation but never a send path,
        // so the flaky SendOnly endpoint below is the *only* place this
        // transaction could propagate.
        let read_client =
            healthy_chain_client(signer.address(), EndpointRole::ReadOnly, "node-0").await;

        // A send-capable endpoint whose eth_sendRawTransaction call always
        // times out -> the only send path available has an uncertain
        // outcome, which must stop the session rather than being silently
        // treated as failure or success.
        let timeout_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_sendRawTransaction", json!("0xdeadbeef"))
            .delay("eth_sendRawTransaction", StdDuration::from_millis(50))
            .build()
            .with_call_timeout(StdDuration::from_millis(1));
        let timeout_client = RpcClient::connect(
            Box::new(timeout_transport),
            1,
            EndpointRole::SendOnly,
            Some("flaky".into()),
        )
        .await
        .unwrap();

        let mut pool = RpcPool::from_clients(1, vec![read_client, timeout_client]);

        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                200,
                valid_mint_response_json(1, 0),
            )
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let req = request(signer.address());

        let err = run_opensea_mint(&opensea, &mut pool, &signer, &req, |_| {})
            .await
            .unwrap_err();
        assert_eq!(err.category(), ErrorCategory::MustStopSession);
    }

    #[tokio::test]
    async fn mint_request_api_timeout_retries_a_bounded_number_of_times_then_fails() {
        let signer = signer();
        let client =
            healthy_chain_client(signer.address(), EndpointRole::ReadWrite, "node-0").await;
        let mut pool = RpcPool::from_clients(1, vec![client]);

        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .timeout("POST", "/api/v2/drops/cool-cats/mint")
            .build();
        let capture = opensea_transport.capture_handle();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let req = request(signer.address());

        let err = run_opensea_mint(&opensea, &mut pool, &signer, &req, |_| {})
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::ApiTimeout)
        ));

        // 1 GET (drop details) + 3 bounded mint-request attempts -- never
        // an unbounded retry loop.
        assert_eq!(capture.call_count(), 4);
    }
}
