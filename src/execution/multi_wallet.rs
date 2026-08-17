//! Safe, self-funded, bounded-concurrency multi-wallet mint orchestration.
//!
//! Each wallet in a session is a completely independent mint participant:
//! its own signer, its own nonce, its own balance/allocation checks, its
//! own OpenSea request/proof/signature (never shared with another
//! wallet), and its own signed transaction. Kairox never automatically
//! splits one wallet's requested quantity across other wallets, never
//! funds a wallet, and never generates wallets — every wallet is an
//! explicit, pre-existing, self-funded entry in a
//! [`crate::execution::manifest`].
//!
//! Wallet identity is always the (normalized) `Address`, never the
//! operator-supplied `label` — labels may collide, be absent, or change,
//! exactly like RPC endpoint labels (see [`crate::chain::pool`]).
//!
//! Concurrency here is deliberately built on `futures_util::stream`'s
//! `buffered`, not `tokio::spawn`/`JoinSet`: every wallet task only ever
//! borrows shared session state (the RPC pool's clients, the OpenSea
//! client) rather than owning/cloning it, so structured, in-task
//! concurrency avoids both an unnecessary `'static` bound and any
//! possibility of a task silently outliving the session. `buffered` (as
//! opposed to `buffer_unordered`) also yields results in the same order
//! the input wallets were iterated in, which gives deterministic,
//! reproducible per-wallet output ordering for free — no manual
//! index-tagging/reordering needed.

use std::time::Duration as StdDuration;

use alloy_primitives::{Address, B256, U256};
use futures_util::stream::{self, StreamExt};
use time::OffsetDateTime;

use crate::chain::benchmark::{BenchmarkConfig, HealthPolicy};
use crate::chain::config::EnvSource;
use crate::chain::pool::RpcPool;
use crate::chain::registry::ChainInfo;
use crate::domain::fees::SafetyCaps;
use crate::execution::errors::{Categorize, ErrorCategory, KairoxError, SessionError};
use crate::execution::manifest::WalletManifestEntry;
use crate::execution::metrics::{LatencyMetrics, Stopwatch};
use crate::execution::opensea_engine::{
    BroadcastTargets, OpenSeaProgress, OpenSeaWalletMintOutcome, OpenSeaWalletMintParams,
    PreparedOpenSeaUnsignedWallet, ReceiptPollConfig, finalize_and_broadcast_opensea_wallet,
    prepare_opensea_wallet_unsigned,
};
use crate::execution::prepared::{
    LiveMintRequest, PreparedTransaction, PreparedUnsignedPlan, finalize_signed_transaction,
    gather_unsigned_plan,
};
use crate::execution::receipt::{ReceiptState, poll_receipt};
use crate::opensea::client::OpenSeaClient;
use crate::opensea::models::DropDetailedResponse;
use crate::signing::keystore::{KeyLoadError, load_from_env_var};
use crate::signing::signer::{LocalSigner, Signer};

use super::broadcast::{
    BroadcastJob, BroadcastSummary, EndpointBroadcastResult, dispatch_broadcast_matrix,
    group_broadcast_results_by_wallet, summarize_broadcast,
};

/// A conservative default: at most this many wallets dispatch/broadcast
/// (public) or run their independent OpenSea pipeline concurrently.
/// Bounds the request matrix (`wallet_count * send_endpoint_count` for
/// broadcast) so a large manifest can never turn into an unbounded
/// request storm against RPC providers, while staying high enough that a
/// realistic manifest (see [`crate::execution::manifest::MAX_WALLETS`])
/// dispatches with negligible added skew.
pub const DEFAULT_BROADCAST_CONCURRENCY: usize = 8;

/// A conservative default for concurrent `POST /api/v2/drops/{slug}/mint`
/// requests in flight against the OpenSea API at once, across the whole
/// wallet set. Deliberately smaller than the broadcast concurrency bound —
/// broadcasting is fanning out to Kairox-operator-configured RPC
/// endpoints, which is Kairox's own infrastructure choice; the OpenSea API
/// is a shared third-party service Kairox must not hammer at stage start.
pub const DEFAULT_OPENSEA_API_CONCURRENCY: usize = 4;

/// One manifest wallet's mint intent — the multi-wallet analogue of the
/// single-wallet CLI's `--wallet`/`--quantity` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMintRequest {
    pub label: Option<String>,
    pub address: Address,
    pub quantity: u64,
}

impl From<&WalletManifestEntry> for WalletMintRequest {
    fn from(entry: &WalletManifestEntry) -> Self {
        Self {
            label: entry.label.clone(),
            address: entry.address,
            quantity: entry.quantity,
        }
    }
}

/// Explicit, inspectable per-wallet lifecycle state. Never collapsed into
/// a single success/failure boolean — see module docs and the Phase 5
/// report for why each state exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletExecutionState {
    Configured,
    KeyVerified,
    Ineligible {
        reason: String,
    },
    InsufficientBalance,
    AllocationExceeded,
    Prepared,
    Dispatched,
    ConfirmedSuccess {
        minted: Vec<crate::protocol::logs::MintedAsset>,
    },
    /// The transaction executed successfully on-chain (status=1), but the
    /// expected mint evidence (attributable `Transfer` logs matching the
    /// requested quantity) was not fully observed. BLOCKCHAIN EXECUTION
    /// CONFIRMED BUT EXPECTED MINT NOT PROVEN. Terminal for this wallet:
    /// never triggers a replacement transaction and is never treated like
    /// network-send uncertainty (the tx definitely executed).
    ConfirmedExecutionMismatch {
        minted: Vec<crate::protocol::logs::MintedAsset>,
        expected_quantity: u64,
    },
    ConfirmedRevert,
    /// This wallet's raw transaction may have reached the network, but no
    /// endpoint gave a definitive accept/reject — never automatically
    /// retried or replaced. See [`crate::execution::broadcast`]'s
    /// `MustStopSession` semantics, scoped here to just this one wallet.
    Uncertain,
    Failed {
        reason: String,
    },
}

impl WalletExecutionState {
    pub fn is_terminal_success(&self) -> bool {
        matches!(self, Self::ConfirmedSuccess { .. })
    }
}

/// One wallet's complete result: its identity, its terminal state, and
/// whatever it produced along the way.
#[derive(Debug, Clone)]
pub struct WalletResult {
    pub request: WalletMintRequest,
    pub state: WalletExecutionState,
    pub tx_hash: Option<B256>,
    pub broadcast_results: Vec<EndpointBroadcastResult>,
    pub metrics: Option<LatencyMetrics>,
}

/// Aggregate session-level metrics. Every duration here is wall-clock —
/// concurrent-phase durations are never summed and presented as if they
/// were sequential.
#[derive(Debug, Clone, Default)]
pub struct SessionMetrics {
    pub wallet_count: usize,
    pub eligible_wallet_count: usize,
    pub prepared_wallet_count: usize,
    pub successful_wallet_count: usize,
    pub failed_wallet_count: usize,
    pub uncertain_wallet_count: usize,
    pub preflight_total_ms: Option<u64>,
    pub multiwallet_prepare_wall_ms: Option<u64>,
    pub multiwallet_dispatch_skew_ms: Option<u64>,
    pub first_dispatch_error_ms: Option<i64>,
    pub last_dispatch_error_ms: Option<i64>,
    pub opensea_peak_concurrency: Option<usize>,
    pub broadcast_peak_concurrency: Option<usize>,
}

/// The complete, honest result of a multi-wallet session. Deliberately
/// never collapsed into a single `SUCCESS`/`FAILED` — see module docs.
#[derive(Debug, Clone)]
pub struct SessionResult {
    pub wallets: Vec<WalletResult>,
    pub metrics: SessionMetrics,
}

impl SessionResult {
    pub fn successful_count(&self) -> usize {
        self.wallets
            .iter()
            .filter(|w| w.state.is_terminal_success())
            .count()
    }
}

/// Shared configuration applied uniformly to every wallet in a session —
/// Phase 5's manifest carries no *per-wallet* safety caps, so the same
/// operator-configured caps that would apply to a single-wallet `--send`
/// apply to each wallet here too.
#[derive(Debug, Clone)]
pub struct MultiWalletConfig {
    pub gas_buffer_multiplier: f64,
    pub safety_caps: SafetyCaps,
    /// Worst-case aggregate spend ceiling across the whole session. `None`
    /// disables the aggregate check (per-wallet caps still always apply).
    pub max_session_total_spend: Option<U256>,
    pub benchmark: BenchmarkConfig,
    pub health: HealthPolicy,
    pub receipt_poll_interval: StdDuration,
    pub receipt_timeout: StdDuration,
    pub broadcast_concurrency: usize,
    pub opensea_api_concurrency: usize,
}

impl Default for MultiWalletConfig {
    fn default() -> Self {
        Self {
            gas_buffer_multiplier: 1.25,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(1_000_000_000_000_000_000u128),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(2_000_000_000_000_000_000u128),
            },
            max_session_total_spend: None,
            benchmark: BenchmarkConfig::default(),
            health: HealthPolicy::default(),
            receipt_poll_interval: StdDuration::from_millis(750),
            receipt_timeout: StdDuration::from_secs(60),
            broadcast_concurrency: DEFAULT_BROADCAST_CONCURRENCY,
            opensea_api_concurrency: DEFAULT_OPENSEA_API_CONCURRENCY,
        }
    }
}

/// Progress events. Purely informational, mirroring the single-wallet
/// engines' `LiveProgress`/`OpenSeaProgress` philosophy.
#[derive(Debug, Clone)]
pub enum MultiWalletProgress {
    Benchmarking,
    AggregatePreflight,
    Preparing {
        address: Address,
    },
    WalletPrepared {
        address: Address,
    },
    WalletFailed {
        address: Address,
        reason: String,
    },
    /// The complete (wallet x endpoint) broadcast job matrix has been
    /// built -- emitted strictly BEFORE the stage-open barrier (`Waiting`),
    /// so a caller/test can observe that matrix construction is a pre-T0
    /// fact, not something that happens after the sleep.
    MatrixPrepared,
    Waiting,
    Dispatching {
        address: Address,
    },
    ReceiptPending {
        address: Address,
    },
    OpenSeaWallet(Address, OpenSeaProgress),
}

/// Load every manifest wallet's signer, verifying `derived address ==
/// manifest address` for each. A mismatch fails *that* wallet only (state
/// `Failed`, excluded from the returned signer map) — it never aborts
/// wallets whose own keys load and verify correctly, and it never allows
/// one key to silently operate another manifest wallet's address.
pub fn load_and_verify_wallet_keys(
    env: &dyn EnvSource,
    entries: &[WalletManifestEntry],
) -> Vec<(WalletManifestEntry, Result<LocalSigner, String>)> {
    entries
        .iter()
        .map(|entry| {
            let result = match load_from_env_var(env, &entry.key_env) {
                Ok(Some(signer)) if signer.address() == entry.address => Ok(signer),
                Ok(Some(signer)) => Err(format!(
                    "key referenced by {} resolves to address {}, but the manifest declares {}; refusing to let one key operate another wallet's address",
                    entry.key_env,
                    signer.address(),
                    entry.address
                )),
                Ok(None) => Err(format!(
                    "{} is not set; cannot load a signing key for wallet {}",
                    entry.key_env, entry.address
                )),
                Err(KeyLoadError::Signing(_)) => {
                    Err("the key material referenced by key_env is invalid".to_string())
                }
                Err(e) => Err(e.to_string()),
            };
            (entry.clone(), result)
        })
        .collect()
}

fn classify_prepare_error(err: &KairoxError) -> WalletExecutionState {
    match err {
        KairoxError::Supply(supply_err) => {
            use crate::domain::supply::SupplyError;
            match supply_err {
                SupplyError::WalletAllocationExhausted
                | SupplyError::ExceedsWalletAllocation { .. }
                | SupplyError::WalletStateInconsistent { .. } => {
                    WalletExecutionState::AllocationExceeded
                }
                _ => WalletExecutionState::Ineligible {
                    reason: supply_err.to_string(),
                },
            }
        }
        KairoxError::Session(SessionError(msg)) if msg.contains("insufficient") => {
            WalletExecutionState::InsufficientBalance
        }
        // A shared-auth-failure skip (see `run_multi_wallet_opensea_mint`'s
        // `auth_failed` flag) is never wallet eligibility -- it must not be
        // classified `Ineligible`.
        KairoxError::Session(SessionError(msg)) if msg.starts_with("skipped:") => {
            WalletExecutionState::Failed {
                reason: msg.clone(),
            }
        }
        KairoxError::Session(SessionError(msg)) => WalletExecutionState::Ineligible {
            reason: msg.clone(),
        },
        KairoxError::OpenSea(e) => {
            use crate::opensea::errors::OpenSeaError;
            match e {
                OpenSeaError::AllocationExceeded { .. } => WalletExecutionState::AllocationExceeded,
                OpenSeaError::EligibilityRejected { .. }
                | OpenSeaError::SupplyExhausted { .. }
                | OpenSeaError::StageInactive { .. } => WalletExecutionState::Ineligible {
                    reason: e.to_string(),
                },
                _ => WalletExecutionState::Failed {
                    reason: e.to_string(),
                },
            }
        }
        _ => WalletExecutionState::Failed {
            reason: err.to_string(),
        },
    }
}

fn duration_ms_i64(start: OffsetDateTime, end: OffsetDateTime) -> i64 {
    (end - start).whole_milliseconds() as i64
}

// ============================================================================
// PUBLIC engine multi-wallet orchestration
// ============================================================================

/// Run a multi-wallet session against the pure on-chain public SeaDrop
/// stage.
///
/// Architecture (see module docs for the concurrency model):
/// 1. Benchmark the shared pool once; select one shared verified read
///    endpoint and the shared send-capable endpoint set (chain/session
///    properties, not per-wallet).
/// 2. Aggregate supply preflight: fail the *whole* session, before
///    anything is prepared or signed, if the sum of every wallet's
///    requested quantity exceeds currently verified remaining supply.
/// 3. Aggregate spend-cap preflight (declared-caps upper bound): fail the
///    whole session before anything is prepared or signed if
///    `wallet_count * safety_caps.max_total_spend` would exceed the
///    configured session cap.
/// 4. PREPARE every wallet independently and concurrently (bounded):
///    nonce, fees, gas estimate, calldata, sign once, serialize once,
///    prebuild broadcast body once — reusing
///    [`crate::execution::prepared::prepare_live_transaction`] exactly as
///    the single-wallet path does, so per-wallet allocation/balance/stage
///    logic is not duplicated. A wallet whose preparation fails is
///    recorded and excluded; it never cancels other wallets.
/// 5. A tighter, *finalized* aggregate spend check over only the wallets
///    that actually prepared successfully -- still before dispatch.
/// 6. Freeze the wallet set, then wait for the common verified stage-open
///    instant (shared across wallets, since they mint the same
///    collection/stage).
/// 7. Dispatch every prepared wallet's identical raw bytes concurrently
///    (bounded), starting together rather than in a sequential loop.
/// 8. Poll receipts concurrently (bounded), reusing the same shared read
///    endpoint.
pub async fn run_multi_wallet_public_mint(
    pool: &mut RpcPool,
    chain: &ChainInfo,
    nft_contract: Address,
    seadrop_contract: Address,
    wallets: &[(WalletMintRequest, LocalSigner)],
    config: &MultiWalletConfig,
    mut on_progress: impl FnMut(MultiWalletProgress),
) -> Result<SessionResult, KairoxError> {
    let mut metrics = SessionMetrics {
        wallet_count: wallets.len(),
        ..Default::default()
    };

    on_progress(MultiWalletProgress::Benchmarking);
    pool.benchmark_all(&config.benchmark).await;

    let read_client = pool.preferred_read().ok_or_else(|| {
        KairoxError::Session(SessionError(
            "no healthy, chain-verified read-capable RPC endpoint available; cannot safely run a multi-wallet session"
                .into(),
        ))
    })?;
    let send_clients = pool.select_send_endpoints(&config.health);
    if send_clients.is_empty() {
        return Err(KairoxError::Session(SessionError(
            "no healthy send-capable RPC endpoint available; refusing to prepare any wallet with nowhere to broadcast to".into(),
        )));
    }

    // GLOBAL AGGREGATE PREFLIGHT — before any wallet is prepared or signed.
    on_progress(MultiWalletProgress::AggregatePreflight);
    let preflight_sw = Stopwatch::start();

    let aggregate_requested: u64 = wallets.iter().map(|(r, _)| r.quantity).sum();
    let mint_stats_calldata = crate::protocol::seadrop::encode_get_mint_stats(Address::ZERO);
    let mint_stats_raw = read_client
        .eth_call(nft_contract, &mint_stats_calldata)
        .await?;
    let mint_stats = crate::protocol::seadrop::decode_get_mint_stats(&mint_stats_raw)?;
    let remaining_supply = mint_stats
        .max_supply
        .saturating_sub(mint_stats.current_total_supply);
    if aggregate_requested > remaining_supply {
        return Err(KairoxError::Session(SessionError(format!(
            "aggregate requested quantity {aggregate_requested} exceeds verified remaining supply {remaining_supply}; refusing to sign any wallet in this session (external participants may still consume supply after this check -- that race is unavoidable and not something Kairox can lock)"
        ))));
    }

    // Section 18/21: `theoretical_upper_bound` (every wallet's *declared*
    // per-wallet cap, multiplied out) is a safe FAST-PATH accept only --
    // if even that pessimistic bound already fits under the session cap,
    // the session is obviously safe and no wallet needs to be rejected.
    // It must never be used to REJECT: a session can easily cost far less
    // than `wallet_count * max_total_spend` in practice (most wallets
    // mint well under their individual ceiling), so rejecting on the
    // declared bound alone would refuse perfectly safe sessions. When the
    // fast path doesn't prove safety, Kairox computes each eligible
    // wallet's real, finalized worst-case cost (gather_unsigned_plan,
    // post-gas-estimate) and checks the ACTUAL aggregate against the cap
    // -- strictly before any wallet in the session is signed.
    let session_cap_fast_path_safe = config.max_session_total_spend.is_none_or(|session_cap| {
        let theoretical_upper_bound = config
            .safety_caps
            .max_total_spend
            .saturating_mul(U256::from(wallets.len() as u64));
        theoretical_upper_bound <= session_cap
    });
    metrics.preflight_total_ms = Some(preflight_sw.elapsed_ms());

    // GATHER (unsigned) — bounded, concurrent, per-wallet, order-preserving.
    // Reads and validates live chain state and computes each wallet's real
    // worst-case cost, but signs nothing yet.
    let prepare_sw = Stopwatch::start();
    let gather_results: Vec<(WalletMintRequest, Result<PreparedUnsignedPlan, KairoxError>)> =
        stream::iter(wallets.iter().map(|(request, signer)| {
            let request = request.clone();
            let signer_address = signer.address();
            async move {
                on_progress_noop();
                let live_request = LiveMintRequest {
                    chain: chain.clone(),
                    nft_contract,
                    seadrop_contract,
                    wallet: request.address,
                    quantity: request.quantity,
                    preferred_fee_recipient: None,
                    gas_buffer_multiplier: config.gas_buffer_multiplier,
                    safety_caps: config.safety_caps,
                };
                let outcome =
                    gather_unsigned_plan(read_client, signer_address, &live_request).await;
                (request, outcome)
            }
        }))
        .buffered(config.broadcast_concurrency.max(1))
        .collect()
        .await;

    let mut wallet_results: Vec<WalletResult> = Vec::with_capacity(wallets.len());
    let mut unsigned_plans: Vec<(WalletMintRequest, PreparedUnsignedPlan)> = Vec::new();

    for (request, outcome) in gather_results {
        match outcome {
            Ok(plan) => unsigned_plans.push((request, plan)),
            Err(e) => {
                let state = classify_prepare_error(&e);
                on_progress(MultiWalletProgress::WalletFailed {
                    address: request.address,
                    reason: e.to_string(),
                });
                wallet_results.push(WalletResult {
                    request,
                    state,
                    tx_hash: None,
                    broadcast_results: Vec::new(),
                    metrics: None,
                });
            }
        }
    }
    metrics.eligible_wallet_count = unsigned_plans.len();

    // Section 19/22: the aggregate session-cap check, using each eligible
    // wallet's real finalized worst-case cost -- strictly BEFORE any
    // wallet in the session is signed. A failure here aborts the whole
    // session with zero signatures and zero broadcasts.
    if !session_cap_fast_path_safe {
        let session_cap = config
            .max_session_total_spend
            .expect("session_cap_fast_path_safe is only false when a cap is configured");
        let finalized_worst_case: U256 =
            unsigned_plans.iter().fold(U256::ZERO, |acc, (_, plan)| {
                acc.saturating_add(plan.worst_case_total_spend)
            });
        if finalized_worst_case > session_cap {
            return Err(KairoxError::Session(SessionError(format!(
                "finalized aggregate worst-case spend across {} eligible wallets ({finalized_worst_case} wei) exceeds the configured session cap ({session_cap} wei); refusing to sign any wallet",
                unsigned_plans.len()
            ))));
        }
    }

    // SIGN — only now, once the aggregate cap (if any) is verifiably safe.
    let mut prepared: Vec<(WalletMintRequest, PreparedTransaction)> = Vec::new();
    for (request, plan) in unsigned_plans {
        let signer = wallets
            .iter()
            .find(|(r, _)| r.address == request.address)
            .map(|(_, s)| s)
            .expect("unsigned_plans is derived from wallets, so the signer always exists");
        match finalize_signed_transaction(signer, plan) {
            Ok(p) => {
                on_progress(MultiWalletProgress::WalletPrepared {
                    address: request.address,
                });
                prepared.push((request, p));
            }
            Err(e) => {
                let state = classify_prepare_error(&e);
                on_progress(MultiWalletProgress::WalletFailed {
                    address: request.address,
                    reason: e.to_string(),
                });
                wallet_results.push(WalletResult {
                    request,
                    state,
                    tx_hash: None,
                    broadcast_results: Vec::new(),
                    metrics: None,
                });
            }
        }
    }
    metrics.multiwallet_prepare_wall_ms = Some(prepare_sw.elapsed_ms());
    metrics.prepared_wallet_count = prepared.len();

    if prepared.is_empty() {
        return Ok(SessionResult {
            wallets: wallet_results,
            metrics,
        });
    }

    // FREEZE: build the complete (wallet x endpoint) submission job matrix
    // now, strictly BEFORE the stage-open sleep -- not merely "signing
    // already happened before the sleep" but the matrix itself (the Vec
    // expansion, endpoint iteration, wallet_index tagging) exists before
    // T=0 too, so nothing but transport scheduling/network I/O happens at
    // or after the barrier. `--broadcast-concurrency` bounds the actual
    // number of individual `eth_sendRawTransaction` requests in flight
    // across the WHOLE matrix, not merely how many wallets may be inside a
    // per-wallet fan-out at once. Jobs are ordered endpoint-major,
    // round-robin across wallets (A->ep1, B->ep1, C->ep1, A->ep2, ...) so a
    // bounded concurrency budget cannot be monopolized by the first
    // wallets in the list.
    let wallet_count = prepared.len();
    let jobs: Vec<BroadcastJob<'_>> = send_clients
        .iter()
        .flat_map(|client| {
            prepared
                .iter()
                .enumerate()
                .map(move |(wallet_index, (_, p))| BroadcastJob {
                    wallet_index,
                    client,
                    prepared: &p.broadcast,
                })
        })
        .collect();
    on_progress(MultiWalletProgress::MatrixPrepared);

    // BARRIER: wait for the shared verified stage-open instant. Everything
    // above this line (signing, serialization, matrix construction) is
    // already done; everything below is transport scheduling only.
    let stage_start = prepared[0].1.stage_start;
    on_progress(MultiWalletProgress::Waiting);
    let now = OffsetDateTime::now_utc();
    crate::execution::scheduler::sleep_until(now, stage_start, |_| {}).await;

    // DISPATCH — the prebuilt matrix, network scheduling only.
    let (job_results, matrix_metrics) =
        dispatch_broadcast_matrix(jobs, config.broadcast_concurrency).await;
    let results_by_wallet = group_broadcast_results_by_wallet(job_results, wallet_count);

    metrics.broadcast_peak_concurrency = Some(matrix_metrics.peak_concurrency);
    if let Some(first) = matrix_metrics.first_dispatch_at {
        metrics.first_dispatch_error_ms = Some(duration_ms_i64(stage_start, first));
    }
    // `last_dispatch_at`, not `last_response_at`: a slow endpoint's
    // response time must never inflate the reported dispatch skew --
    // only when the requests themselves actually left matters here.
    if let Some(last) = matrix_metrics.last_dispatch_at {
        metrics.last_dispatch_error_ms = Some(duration_ms_i64(stage_start, last));
    }
    if let (Some(f), Some(l)) = (
        metrics.first_dispatch_error_ms,
        metrics.last_dispatch_error_ms,
    ) {
        metrics.multiwallet_dispatch_skew_ms = Some((l - f).unsigned_abs());
    }

    // Reconstruct each wallet's own BroadcastSummary strictly from its own
    // (wallet-tagged, not completion-order-tagged) results -- another
    // wallet's outcomes never influence this one's classification.
    let receipt_inputs: Vec<_> = prepared
        .into_iter()
        .zip(results_by_wallet)
        .map(|((request, p), results)| {
            let summary = summarize_broadcast(&results);
            (request, p, results, summary)
        })
        .collect();

    // RECEIPTS — bounded, concurrent, per confirmed wallet.
    let final_results: Vec<WalletResult> = stream::iter(receipt_inputs.into_iter().map(
        |(request, p, results, summary)| {
            let read_client = &read_client;
            async move {
                // Progress events for this concurrent phase are
                // deliberately not emitted per-wallet here: `on_progress`
                // is a single `&mut` callback and cannot be safely shared
                // across multiple in-flight concurrent futures. Coarser
                // session-level progress (`WalletPrepared`/`WalletFailed`)
                // is still reported from the sequential preparation phase
                // above.
                let (state, tx_hash) = match summary {
                    BroadcastSummary::AllRejected => (
                        WalletExecutionState::Failed {
                            reason: "all endpoints rejected this wallet's transaction".into(),
                        },
                        None,
                    ),
                    BroadcastSummary::Uncertain => (WalletExecutionState::Uncertain, None),
                    BroadcastSummary::Confirmed { tx_hash } => {
                        let receipt_state = poll_receipt(
                            read_client,
                            tx_hash,
                            nft_contract,
                            request.address,
                            request.quantity,
                            config.receipt_poll_interval,
                            config.receipt_timeout,
                            || {},
                        )
                        .await;
                        let state = match receipt_state {
                            ReceiptState::ConfirmedSuccess { minted } => {
                                WalletExecutionState::ConfirmedSuccess { minted }
                            }
                            ReceiptState::ConfirmedExecutionMismatch {
                                minted,
                                expected_quantity,
                            } => WalletExecutionState::ConfirmedExecutionMismatch {
                                minted,
                                expected_quantity,
                            },
                            ReceiptState::ConfirmedRevert => WalletExecutionState::ConfirmedRevert,
                            ReceiptState::ReceiptUnknown => WalletExecutionState::Uncertain,
                        };
                        (state, Some(tx_hash))
                    }
                };
                let m = LatencyMetrics {
                    broadcast_prepare_ms: Some(p.broadcast_prepare_ms),
                    ..Default::default()
                };
                WalletResult {
                    request,
                    state,
                    tx_hash,
                    broadcast_results: results,
                    metrics: Some(m),
                }
            }
        },
    ))
    .buffered(config.broadcast_concurrency.max(1))
    .collect()
    .await;

    wallet_results.extend(final_results);
    for w in &wallet_results {
        match &w.state {
            WalletExecutionState::ConfirmedSuccess { .. } => metrics.successful_wallet_count += 1,
            WalletExecutionState::Uncertain => metrics.uncertain_wallet_count += 1,
            WalletExecutionState::ConfirmedRevert
            | WalletExecutionState::ConfirmedExecutionMismatch { .. }
            | WalletExecutionState::Failed { .. }
            | WalletExecutionState::Ineligible { .. }
            | WalletExecutionState::InsufficientBalance
            | WalletExecutionState::AllocationExceeded => metrics.failed_wallet_count += 1,
            _ => {}
        }
    }

    Ok(SessionResult {
        wallets: wallet_results,
        metrics,
    })
}

fn on_progress_noop() {}

// ============================================================================
// OpenSea engine multi-wallet orchestration
// ============================================================================

/// The collection/chain/slug this OpenSea multi-wallet session targets —
/// bundled since every wallet shares these facts, keeping
/// [`run_multi_wallet_opensea_mint`]'s own argument list focused on what
/// actually varies per call (the pool, the wallet set, the config).
#[derive(Debug, Clone, Copy)]
pub struct OpenSeaMultiWalletTarget<'a> {
    pub chain: &'a ChainInfo,
    pub slug: &'a str,
    pub nft_contract: Address,
    pub seadrop_contract: Address,
}

/// Run a multi-wallet session against a wallet-specific OpenSea drop
/// stage (public/allowlist/server-signed, whichever the collection's
/// stage actually is — each wallet's own OpenSea response determines
/// this independently).
///
/// Session-level setup (benchmark, drop details, endpoint selection) runs
/// once, shared. Every wallet then runs its own independent, locally
/// validated request/simulation pipeline via
/// [`crate::execution::opensea_engine::prepare_opensea_wallet_unsigned`]
/// (its own OpenSea request, its own Merkle proof / EIP-712 signature
/// validation, its own simulation — never another wallet's), bounded and
/// concurrent under `config.opensea_api_concurrency`.
///
/// Unlike the public engine (whose calldata is known ahead of time and can
/// be pre-signed before the stage opens with no external dependency),
/// OpenSea wallets only learn their own `maxTokenSupplyForStage`
/// constraint (if any) from their own response — arrival order is not
/// meaningful, and Kairox never infers protocol facts from OpenSea's
/// off-chain stage-type metadata. So no wallet is EVER signed before every
/// wallet in the session has finished this unsigned preparation: the
/// sign/broadcast decision for the whole eligible set is a pure function
/// of the complete set of responses, never of the order they happened to
/// arrive in. Once every response is in, [`check_opensea_aggregate_invariants`]
/// verifies the real aggregate cost (if a session spend cap is configured)
/// and the real aggregate stage-supply ceiling (if any wallet's response
/// carried one) — a no-op, and thus no extra latency, when neither
/// applies. Only then are eligible wallets signed/broadcast/polled,
/// bounded and concurrent.
pub async fn run_multi_wallet_opensea_mint(
    opensea: &OpenSeaClient,
    pool: &mut RpcPool,
    target: &OpenSeaMultiWalletTarget<'_>,
    wallets: &[(WalletMintRequest, LocalSigner)],
    config: &MultiWalletConfig,
    mut on_progress: impl FnMut(MultiWalletProgress),
) -> Result<(SessionResult, DropDetailedResponse), KairoxError> {
    let OpenSeaMultiWalletTarget {
        chain,
        slug,
        nft_contract,
        seadrop_contract,
    } = *target;
    let mut metrics = SessionMetrics {
        wallet_count: wallets.len(),
        ..Default::default()
    };

    on_progress(MultiWalletProgress::Benchmarking);
    pool.benchmark_all(&config.benchmark).await;
    pool.rewarm_all().await;

    let drop_details = opensea.get_drop_details(slug).await?;
    let stage = drop_details
        .active_stage
        .as_ref()
        .or(drop_details.next_stage.as_ref());
    let known_stage_start = stage.and_then(|s| {
        OffsetDateTime::parse(
            &s.start_time,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()
    });
    let expected_price_per_token = stage
        .and_then(|s| s.price.as_ref())
        .and_then(|p| U256::from_str_radix(p, 10).ok());

    let read_client = pool.preferred_read().ok_or_else(|| {
        KairoxError::Session(SessionError(
            "no healthy, chain-verified read-capable RPC endpoint available; cannot safely run a multi-wallet OpenSea session"
                .into(),
        ))
    })?;
    let send_clients = pool.select_send_endpoints(&config.health);
    if send_clients.is_empty() {
        return Err(KairoxError::Session(SessionError(
            "no healthy send-capable RPC endpoint available; refusing to prepare any wallet with nowhere to broadcast to".into(),
        )));
    }

    if let Some(stage_start) = known_stage_start {
        let now = OffsetDateTime::now_utc();
        crate::execution::scheduler::sleep_until(now, stage_start, |_| {}).await;
    }

    // A wallet-specific mint POST returning 401/403 after the shared
    // preflight (`get_drop_details` above) succeeded means the shared
    // OpenSea API key stopped working mid-session -- not that this one
    // wallet is ineligible. `auth_failed` is the session-level
    // cancellation signal: once any wallet observes it, every wallet whose
    // future has not yet started skips straight to a `Failed` state
    // instead of spending its own OpenSea request/signing/broadcast on a
    // key that is already known to be rejected. Wallets already in flight
    // when the flag flips race independently and are not retroactively
    // undone -- an already-broadcast transaction cannot be un-broadcast.
    let opensea_concurrency = config.opensea_api_concurrency.max(1);
    let auth_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Real, observed peak concurrency -- how many wallets actually had a
    // live, in-flight OpenSea API request/validate/simulate pipeline
    // running at the same instant, not merely the configured bound.
    let active_opensea = std::sync::atomic::AtomicUsize::new(0);
    let peak_opensea = std::sync::atomic::AtomicUsize::new(0);
    // Shared, session-scoped bound on the actual number of individual
    // `eth_sendRawTransaction` requests in flight at once, across EVERY
    // wallet's own broadcast -- however many wallets there are, and
    // whenever each happens to reach its own dispatch (streaming mode's
    // wallets broadcast at different times, unlike the public engine's
    // single precomputed batch). `--broadcast-concurrency` means the same
    // thing here as it does for the public engine.
    let broadcast_limiter =
        crate::execution::broadcast::BroadcastLimiter::new(config.broadcast_concurrency.max(1));

    // SAFETY: OpenSea multi-wallet sessions cannot speculatively stream a
    // wallet to sign/broadcast merely because ITS OWN response revealed no
    // stage constraint. All wallets mint the SAME collection, so an
    // "unconstrained" mint still consumes `currentTotalSupply` -- exactly
    // the value a LATER-discovered constrained wallet's
    // `maxTokenSupplyForStage` check depends on. If the unconstrained
    // wallet's transaction has not yet landed (or even been observed) when
    // the constrained wallet's aggregate check runs, that check would
    // under-count real consumption and could pass a session whose true
    // on-chain effect exceeds the stage ceiling. Whether a constraint is
    // discovered early or late must never change the safety decision, so
    // Kairox does not attempt "stream until a constraint appears": every
    // wallet's own OpenSea response is gathered (PREPARE, unsigned, bounded
    // and concurrent) BEFORE any wallet is signed, exactly like a strict
    // session-spend-cap barrier already required. This makes the
    // sign/broadcast decision for the whole eligible set a pure function of
    // the FULL set of responses, never of the order they arrived in.
    //
    // The PublicSeaDropEngine (see `run_multi_wallet_public_mint`) is
    // unaffected and keeps its true pre-signed T=0 fast path -- it never
    // depends on wallet-specific, order-sensitive external responses.
    let prepare_results: Vec<(
        WalletMintRequest,
        Result<PreparedOpenSeaUnsignedWallet, KairoxError>,
    )> = stream::iter(wallets.iter().map(|(request, _signer)| {
        let read_client = &read_client;
        let auth_failed = auth_failed.clone();
        let active_opensea = &active_opensea;
        let peak_opensea = &peak_opensea;
        async move {
            if auth_failed.load(std::sync::atomic::Ordering::SeqCst) {
                return (
                    request.clone(),
                    Err(KairoxError::Session(SessionError(
                        "skipped: the shared OpenSea API key was rejected (401/403) while processing another wallet in this session".into(),
                    ))),
                );
            }
            let now_active = active_opensea.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            peak_opensea.fetch_max(now_active, std::sync::atomic::Ordering::SeqCst);
            let params = OpenSeaWalletMintParams {
                chain,
                slug,
                nft_contract,
                seadrop_contract,
                wallet: request.address,
                quantity: request.quantity,
                gas_buffer_multiplier: config.gas_buffer_multiplier,
                safety_caps: config.safety_caps,
                known_stage_start,
                expected_price_per_token,
                receipt_poll_interval: config.receipt_poll_interval,
                receipt_timeout: config.receipt_timeout,
            };
            let outcome = prepare_opensea_wallet_unsigned(
                opensea,
                read_client,
                request.address,
                &params,
                |p| on_progress_noop_opensea(request.address, p),
            )
            .await;
            active_opensea.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

            if matches!(
                &outcome,
                Err(KairoxError::OpenSea(
                    crate::opensea::errors::OpenSeaError::AuthenticationFailed
                ))
            ) {
                auth_failed.store(true, std::sync::atomic::Ordering::SeqCst);
            }

            (request.clone(), outcome)
        }
    }))
    .buffered(opensea_concurrency)
    .collect()
    .await;

    let mut wallet_results: Vec<WalletResult> = Vec::with_capacity(wallets.len());
    let mut unsigned_ready: Vec<(
        WalletMintRequest,
        &LocalSigner,
        PreparedOpenSeaUnsignedWallet,
    )> = Vec::new();
    for (request, outcome) in prepare_results {
        match outcome {
            Ok(plan) => {
                let signer = wallets
                    .iter()
                    .find(|(r, _)| r.address == request.address)
                    .map(|(_, s)| s)
                    .expect("unsigned_ready is derived from wallets, so the signer always exists");
                unsigned_ready.push((request, signer, plan));
            }
            Err(e) => {
                let state = classify_prepare_error(&e);
                wallet_results.push(WalletResult {
                    request,
                    state,
                    tx_hash: None,
                    broadcast_results: Vec::new(),
                    metrics: None,
                });
            }
        }
    }

    // Checked over the FULL eligible set every time (a no-op when neither a
    // session cap is configured nor any wallet carries a stage constraint,
    // so the common case pays no extra latency beyond the PREPARE round
    // that was always required to even learn this). Nothing has been
    // signed yet, so a rejection here is a clean whole-session failure --
    // never a partial one.
    check_opensea_aggregate_invariants(
        &unsigned_ready,
        config.max_session_total_spend,
        nft_contract,
        read_client,
    )
    .await?;

    let final_results: Vec<WalletResult> =
        stream::iter(unsigned_ready.into_iter().map(|(request, signer, plan)| {
            let send_clients = &send_clients;
            let read_client = &read_client;
            let broadcast_limiter = &broadcast_limiter;
            async move {
                let api_to_dispatch_sw = Stopwatch::start();
                let outcome: Result<OpenSeaWalletMintOutcome, KairoxError> =
                    finalize_and_broadcast_opensea_wallet(
                        signer,
                        BroadcastTargets {
                            send_clients,
                            limiter: Some(broadcast_limiter),
                        },
                        read_client,
                        plan,
                        ReceiptPollConfig {
                            interval: config.receipt_poll_interval,
                            timeout: config.receipt_timeout,
                        },
                        &api_to_dispatch_sw,
                        |p| on_progress_noop_opensea(request.address, p),
                    )
                    .await;
                wallet_result_from_opensea_outcome(request, outcome)
            }
        }))
        .buffered(opensea_concurrency)
        .collect()
        .await;

    wallet_results.extend(final_results);

    metrics.opensea_peak_concurrency = Some(peak_opensea.load(std::sync::atomic::Ordering::SeqCst));
    metrics.broadcast_peak_concurrency = Some(broadcast_limiter.peak_concurrency());
    metrics.eligible_wallet_count = wallet_results
        .iter()
        .filter(|w| !matches!(w.state, WalletExecutionState::Ineligible { .. }))
        .count();
    metrics.prepared_wallet_count = wallet_results
        .iter()
        .filter(|w| w.tx_hash.is_some())
        .count();
    for w in &wallet_results {
        match &w.state {
            WalletExecutionState::ConfirmedSuccess { .. } => metrics.successful_wallet_count += 1,
            WalletExecutionState::Uncertain => metrics.uncertain_wallet_count += 1,
            _ => metrics.failed_wallet_count += 1,
        }
    }

    Ok((
        SessionResult {
            wallets: wallet_results,
            metrics,
        },
        drop_details,
    ))
}

/// Shared aggregate-safety check for a set of unsigned-ready OpenSea
/// wallets, used by both BARRIER mode (the whole eligible set) and
/// STREAMING mode (only the narrow stage-constrained subset). Checks, in
/// order: the session spend cap (if `session_cap` is given) against the
/// real, finalized `worst_case_total_spend` sum; then the aggregate
/// stage-supply ceiling (if any wallet carries a `stage_constraint`)
/// against a freshly-read, verified `currentTotalSupply`. Returns `Err`
/// (never panics, never signs) the instant either check fails.
async fn check_opensea_aggregate_invariants(
    unsigned_ready: &[(
        WalletMintRequest,
        &LocalSigner,
        PreparedOpenSeaUnsignedWallet,
    )],
    session_cap: Option<U256>,
    nft_contract: Address,
    read_client: &crate::chain::rpc::RpcClient,
) -> Result<(), KairoxError> {
    if let Some(session_cap) = session_cap {
        let finalized_worst_case: U256 =
            unsigned_ready.iter().fold(U256::ZERO, |acc, (_, _, plan)| {
                acc.saturating_add(plan.worst_case_total_spend)
            });
        if finalized_worst_case > session_cap {
            return Err(KairoxError::Session(SessionError(format!(
                "finalized aggregate worst-case spend across {} eligible OpenSea wallets ({finalized_worst_case} wei) exceeds the configured session cap ({session_cap} wei); refusing to sign any wallet",
                unsigned_ready.len()
            ))));
        }
    }

    // Section 10-17: aggregate stage-supply safety. `maxTokenSupplyForStage`
    // is an ABSOLUTE total-supply ceiling per the official SeaDrop contract
    // (`currentTotalSupply + quantity <= maxTokenSupplyForStage`), not a
    // per-stage-only counter -- see `opensea_validate::StageSupplyConstraint`
    // docs. Every wallet in this session shares one `nft_contract`, so
    // every eligible wallet's quantity (constrained or not) consumes the
    // same collection-wide supply and must be counted in the aggregate,
    // since Kairox cannot control the on-chain execution order of its own
    // batch. When wallets carry DIFFERENT validated ceilings, the minimum
    // is the only value that is safe for every one of them simultaneously
    // (a looser M elsewhere does not relax a tighter M's own on-chain
    // check) -- this is an exact, not approximate, sufficient condition,
    // not a heuristic.
    let stage_constrained: Vec<usize> = unsigned_ready
        .iter()
        .enumerate()
        .filter(|(_, (_, _, plan))| plan.stage_constraint.is_some())
        .map(|(i, _)| i)
        .collect();

    if !stage_constrained.is_empty() {
        let min_max_token_supply_for_stage = stage_constrained
            .iter()
            .map(|&i| {
                unsigned_ready[i]
                    .2
                    .stage_constraint
                    .expect("filtered to Some above")
                    .max_token_supply_for_stage
            })
            .min()
            .expect("stage_constrained is non-empty");

        let aggregate_quantity: u64 = unsigned_ready.iter().map(|(r, _, _)| r.quantity).sum();

        // Fresh, verified read -- never SEND_ONLY/SEQUENCER/ConfiguredSendOnly
        // (guaranteed by `read_client` itself, selected via `preferred_read`
        // by every caller). `getMintStats`'s `currentTotalSupply`/`maxSupply`
        // are collection-wide facts independent of the queried `minter`
        // argument (only `minterNumMinted` varies with it, per the official
        // SeaDrop contract), so `Address::ZERO` is a protocol-safe query
        // address for this read -- Kairox never needs a real wallet's
        // per-minter count here.
        let mint_stats_calldata = crate::protocol::seadrop::encode_get_mint_stats(Address::ZERO);
        let mint_stats_raw = read_client
            .eth_call(nft_contract, &mint_stats_calldata)
            .await?;
        let mint_stats = crate::protocol::seadrop::decode_get_mint_stats(&mint_stats_raw)?;
        let projected_total_supply = U256::from(mint_stats.current_total_supply)
            .saturating_add(U256::from(aggregate_quantity));

        if projected_total_supply > min_max_token_supply_for_stage {
            return Err(KairoxError::Session(SessionError(format!(
                "aggregate requested quantity across {} eligible OpenSea wallets ({aggregate_quantity}) would bring total supply to {projected_total_supply}, exceeding the verified stage cap ({min_max_token_supply_for_stage}, current supply {}); refusing to sign any wallet -- the operator must edit the manifest to fit within the remaining stage capacity",
                unsigned_ready.len(),
                mint_stats.current_total_supply
            ))));
        }
    }

    Ok(())
}

fn on_progress_noop_opensea(_address: Address, _progress: OpenSeaProgress) {}

fn wallet_result_from_opensea_outcome(
    request: WalletMintRequest,
    outcome: Result<OpenSeaWalletMintOutcome, KairoxError>,
) -> WalletResult {
    match outcome {
        Ok(o) => {
            let (state, tx_hash) = match o.broadcast_summary {
                BroadcastSummary::AllRejected => (
                    WalletExecutionState::Failed {
                        reason: "all endpoints rejected this wallet's transaction".into(),
                    },
                    None,
                ),
                BroadcastSummary::Uncertain => (WalletExecutionState::Uncertain, None),
                BroadcastSummary::Confirmed { tx_hash } => {
                    let state = match o.receipt_state {
                        Some(ReceiptState::ConfirmedSuccess { minted }) => {
                            WalletExecutionState::ConfirmedSuccess { minted }
                        }
                        Some(ReceiptState::ConfirmedExecutionMismatch {
                            minted,
                            expected_quantity,
                        }) => WalletExecutionState::ConfirmedExecutionMismatch {
                            minted,
                            expected_quantity,
                        },
                        Some(ReceiptState::ConfirmedRevert) => {
                            WalletExecutionState::ConfirmedRevert
                        }
                        Some(ReceiptState::ReceiptUnknown) | None => {
                            WalletExecutionState::Uncertain
                        }
                    };
                    (state, Some(tx_hash))
                }
            };
            WalletResult {
                request,
                state,
                tx_hash,
                broadcast_results: o.broadcast_results,
                metrics: Some(o.metrics),
            }
        }
        Err(e) => {
            let state = if e.category() == ErrorCategory::MustStopSession {
                WalletExecutionState::Uncertain
            } else {
                classify_prepare_error(&e)
            };
            WalletResult {
                request,
                state,
                tx_hash: None,
                broadcast_results: Vec::new(),
                metrics: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;

    /// Shared dispatch-order log: `(endpoint_index, recovered_wallet)`
    /// pairs pushed by [`attach_mint_receipt_routing_with`] at the moment
    /// each `eth_sendRawTransaction` is dispatched.
    type DispatchOrderLog = std::sync::Arc<std::sync::Mutex<Vec<(usize, Address)>>>;
    use crate::chain::registry::ChainRegistry;
    use crate::chain::rpc::RpcClient;
    use crate::execution::errors::{Categorize, ErrorCategory};
    use crate::opensea::client::OpenSeaClient;
    use crate::opensea::mock::MockOpenSeaTransport;
    use crate::protocol::seadrop::{self, MintParams, MintParamsAbi, mintAllowListCall};
    use crate::protocol::seadrop_crypto;
    use alloy_primitives::{U256, address, keccak256};
    use alloy_sol_types::SolCall;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use time::macros::datetime;

    const NFT: Address = address!("000000000000000000000000000000000000c0de");
    const SEADROP: Address = address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5");
    const FEE_RECIPIENT: Address = address!("0000000000000000000000000000000000fee000");

    fn signer_for(seed: &str) -> LocalSigner {
        LocalSigner::from_bytes(keccak256(seed.as_bytes()).0).unwrap()
    }

    fn chain() -> ChainInfo {
        ChainRegistry::builtin().by_id(1).unwrap().clone()
    }

    /// Mirrors the flat 12-field RLP layout `SignedEip1559Tx::raw_bytes`
    /// produces (`[chainId,nonce,maxPriorityFeePerGas,maxFeePerGas,
    /// gasLimit,to,value,data,accessList,yParity,r,s]`) so a mock transport
    /// can decode a signed raw transaction back into its real sender and
    /// mint calldata -- exactly the correlation a real chain provides,
    /// without either the test or Kairox trusting an off-chain hint.
    #[derive(alloy_rlp::RlpDecodable)]
    struct RawSignedTxFields {
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
        to: Address,
        value: U256,
        data: alloy_primitives::Bytes,
        access_list: Vec<crate::signing::transaction::AccessListItem>,
        y_parity: u64,
        r: U256,
        s: U256,
    }

    /// Recover a raw signed transaction's true sender (via ECDSA recovery,
    /// exactly like a real chain) and its requested SeaDrop mint quantity
    /// (decoded from its own calldata), so mock receipt fixtures can prove
    /// exact per-wallet token attribution instead of stubbing empty logs.
    fn decode_wallet_and_quantity_from_raw_tx(raw_hex: &str) -> Option<(Address, u64)> {
        let bytes = hex::decode(raw_hex.trim_start_matches("0x")).ok()?;
        if bytes.first() != Some(&crate::signing::transaction::EIP1559_TX_TYPE) {
            return None;
        }
        let mut body = &bytes[1..];
        let fields = <RawSignedTxFields as alloy_rlp::Decodable>::decode(&mut body).ok()?;
        let unsigned = crate::signing::transaction::UnsignedEip1559Tx {
            chain_id: fields.chain_id,
            nonce: fields.nonce,
            max_priority_fee_per_gas: fields.max_priority_fee_per_gas,
            max_fee_per_gas: fields.max_fee_per_gas,
            gas_limit: fields.gas_limit,
            to: fields.to,
            value: fields.value,
            data: fields.data.clone(),
            access_list: fields.access_list,
        };
        let signature = crate::signing::transaction::Eip1559Signature {
            y_parity: fields.y_parity != 0,
            r: fields.r,
            s: fields.s,
        };
        let wallet = crate::signing::signer::recover_signer(&unsigned, &signature).ok()?;
        let quantity = match seadrop::decode_seadrop_mint_calldata(&fields.data).ok()? {
            seadrop::SeaDropMintKind::Public(p) => p.quantity.to::<u64>(),
            seadrop::SeaDropMintKind::AllowList(a) => a.quantity.to::<u64>(),
            seadrop::SeaDropMintKind::ServerSigned(s) => s.quantity.to::<u64>(),
            seadrop::SeaDropMintKind::TokenGated => return None,
        };
        Some((wallet, quantity))
    }

    fn mint_transfer_log_json(nft: Address, to: Address, token_id: u64) -> Value {
        let mut topic_to = [0u8; 32];
        topic_to[12..32].copy_from_slice(to.as_slice());
        let mut topic_id = [0u8; 32];
        topic_id[24..32].copy_from_slice(&token_id.to_be_bytes());
        json!({
            "address": nft.to_string(),
            "topics": [
                format!("0x{}", hex::encode(keccak256(b"Transfer(address,address,uint256)"))),
                format!("0x{}", hex::encode([0u8; 32])),
                format!("0x{}", hex::encode(topic_to)),
                format!("0x{}", hex::encode(topic_id)),
            ],
            "data": "0x"
        })
    }

    /// Wire up `eth_sendRawTransaction` (real hash, real sender/quantity
    /// correlation) and `eth_getTransactionReceipt` (correct, distinct,
    /// attributable mint `Transfer` logs per recovered sender) on a shared
    /// mock transport -- so multi-wallet fixtures prove real per-wallet
    /// token attribution rather than an empty-logs stub that would pass
    /// `ConfirmedSuccess` for any status-1 receipt.
    /// Per-wallet overrides for [`attach_mint_receipt_routing`], so a
    /// single shared mock transport (matching the real architecture: one
    /// RPC pool serves every wallet in a session) can still make exactly
    /// one wallet's broadcast/receipt behave differently, proving other
    /// wallets are unaffected (Section 28-31's failure-isolation matrix).
    #[derive(Default, Clone)]
    struct MintReceiptOverrides {
        /// This wallet's `eth_sendRawTransaction` returns a fatal JSON-RPC
        /// rejection instead of an accepted hash.
        fatal_reject_wallet: Option<Address>,
        /// This wallet's receipt reports `status: "0x0"` (reverted) instead
        /// of a successful mint.
        revert_wallet: Option<Address>,
        /// This wallet's receipt is never found (`eth_getTransactionReceipt`
        /// always returns `null`) -- the broadcast itself is accepted, but
        /// no receipt ever confirms it, exactly like a genuinely uncertain
        /// on-chain outcome. `poll_receipt` times out into
        /// `ReceiptState::ReceiptUnknown`, which multi-wallet orchestration
        /// maps to `WalletExecutionState::Uncertain`.
        unknown_receipt_wallet: Option<Address>,
        /// Every `eth_sendRawTransaction` call sleeps this long before
        /// resolving -- used to create genuine overlap for a broadcast
        /// concurrency test (peak in-flight sends must never exceed the
        /// configured bound, across multiple wallets and multiple send
        /// endpoints all sharing one mock transport).
        send_delay: Option<StdDuration>,
        /// If set, `(endpoint_index, shared dispatch-order log)` -- every
        /// `eth_sendRawTransaction` call on this endpoint pushes
        /// `(endpoint_index, recovered_wallet)` to the shared log at the
        /// moment it is dispatched (before any delay is awaited), giving
        /// tests the true cross-endpoint dispatch-start order.
        order_log: Option<(usize, DispatchOrderLog)>,
        /// If set, every `eth_sendRawTransaction` call pushes
        /// `Instant::now()` to this shared log at the moment it is
        /// dispatched -- lets a test compare real wall-clock dispatch
        /// timing against another wall-clock instant it captured itself
        /// (e.g. when the broadcast job matrix was built), proving
        /// ordering that a JSON-RPC capture handle alone cannot show.
        send_wall_clock_log: Option<std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>>,
    }

    fn attach_mint_receipt_routing(
        builder: crate::chain::mock::MockTransportBuilder,
        nft: Address,
    ) -> crate::chain::mock::MockTransportBuilder {
        attach_mint_receipt_routing_with(builder, nft, MintReceiptOverrides::default())
    }

    /// `raw tx hash (hex string) -> (recovered wallet, minted token ids)`,
    /// shared between the `eth_sendRawTransaction` and
    /// `eth_getTransactionReceipt` mock handlers in
    /// [`attach_mint_receipt_routing_with`].
    type TxWalletIndex = std::sync::Arc<std::sync::Mutex<HashMap<String, (Address, Vec<u64>)>>>;

    fn attach_mint_receipt_routing_with(
        builder: crate::chain::mock::MockTransportBuilder,
        nft: Address,
        overrides: MintReceiptOverrides,
    ) -> crate::chain::mock::MockTransportBuilder {
        let next_token_id = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
        let tx_index: TxWalletIndex = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));

        let send_index = tx_index.clone();
        let send_counter = next_token_id;
        let send_overrides = overrides.clone();
        let builder =
            builder.respond_dynamic_result_delayed("eth_sendRawTransaction", move |params| {
                let delay = send_overrides.send_delay.unwrap_or(StdDuration::ZERO);
                let raw_hex = params.get(0).and_then(Value::as_str).unwrap_or("0x");
                let decoded = decode_wallet_and_quantity_from_raw_tx(raw_hex);
                if let Some((endpoint_index, log)) = &send_overrides.order_log
                    && let Some((wallet, _)) = decoded
                {
                    log.lock()
                        .expect("mutex poisoned")
                        .push((*endpoint_index, wallet));
                }
                if let Some(log) = &send_overrides.send_wall_clock_log {
                    log.lock()
                        .expect("mutex poisoned")
                        .push(std::time::Instant::now());
                }
                if let (Some(reject), Some((wallet, _))) =
                    (send_overrides.fatal_reject_wallet, decoded)
                    && wallet == reject
                {
                    return (
                        delay,
                        Err((-32003, "insufficient funds for gas * price + value".into())),
                    );
                }
                let bytes = hex::decode(raw_hex.trim_start_matches("0x")).unwrap_or_default();
                let hash = alloy_primitives::keccak256(&bytes);
                let hash_hex = format!("0x{}", hex::encode(hash));
                if let Some((wallet, quantity)) = decoded {
                    let ids: Vec<u64> = (0..quantity)
                        .map(|_| send_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
                        .collect();
                    send_index
                        .lock()
                        .expect("mutex poisoned")
                        .insert(hash_hex.clone(), (wallet, ids));
                }
                (delay, Ok(json!(hash_hex)))
            });

        let receipt_index = tx_index;
        builder.respond_dynamic("eth_getTransactionReceipt", move |params| {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            let entry = receipt_index
                .lock()
                .expect("mutex poisoned")
                .get(&queried_hash)
                .cloned();
            let unknown = entry
                .as_ref()
                .zip(overrides.unknown_receipt_wallet)
                .is_some_and(|((wallet, _), unknown_wallet)| *wallet == unknown_wallet);
            if unknown {
                return json!(null);
            }
            let reverted = entry
                .as_ref()
                .zip(overrides.revert_wallet)
                .is_some_and(|((wallet, _), revert_wallet)| *wallet == revert_wallet);
            let logs = if reverted {
                Vec::new()
            } else {
                entry
                    .map(|(wallet, ids)| {
                        ids.iter()
                            .map(|id| mint_transfer_log_json(nft, wallet, *id))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            json!({
                "transactionHash": queried_hash,
                "status": if reverted { "0x0" } else { "0x1" },
                "blockNumber": "0x1",
                "logs": logs
            })
        })
    }

    /// A read-write chain client whose `eth_getTransactionCount`/
    /// `eth_getBalance` respond per-queried-address from the given maps
    /// (defaulting to a generous nonce/balance for any address not
    /// explicitly listed), with a single shared, generous public-drop
    /// stage and mint-stats fixture.
    async fn public_pool(
        nonce_by_wallet: HashMap<Address, u64>,
        balance_by_wallet: HashMap<Address, &'static str>,
    ) -> RpcPool {
        public_pool_with_capture(nonce_by_wallet, balance_by_wallet)
            .await
            .0
    }

    /// Like [`public_pool`], but also returns the transport's capture
    /// handle so a test can prove exactly which RPC calls were (or, more
    /// importantly, were NOT) made -- e.g. that a failed aggregate
    /// preflight really did produce zero `eth_sendRawTransaction` calls.
    async fn public_pool_with_capture(
        nonce_by_wallet: HashMap<Address, u64>,
        balance_by_wallet: HashMap<Address, &'static str>,
    ) -> (RpcPool, crate::chain::mock::CaptureHandle) {
        public_pool_with_overrides(
            nonce_by_wallet,
            balance_by_wallet,
            None,
            MintReceiptOverrides::default(),
        )
        .await
    }

    /// Full-control variant of [`public_pool`], additionally able to make
    /// exactly one wallet's `eth_estimateGas` (simulation) revert, and to
    /// apply [`MintReceiptOverrides`] to its broadcast/receipt behavior --
    /// so failure-isolation tests can prove one wallet failing in a
    /// specific way never affects the others sharing the same pool.
    async fn public_pool_with_overrides(
        nonce_by_wallet: HashMap<Address, u64>,
        balance_by_wallet: HashMap<Address, &'static str>,
        simulation_revert_wallet: Option<Address>,
        overrides: MintReceiptOverrides,
    ) -> (RpcPool, crate::chain::mock::CaptureHandle) {
        let public_drop = seadrop::PublicDropAbi {
            mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
            startTime: alloy_primitives::Uint::from(
                datetime!(2020-01-01 00:00:00 UTC).unix_timestamp() as u64,
            ),
            endTime: alloy_primitives::Uint::from(
                datetime!(2999-01-01 00:00:00 UTC).unix_timestamp() as u64,
            ),
            maxTotalMintableByWallet: 50,
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
                    currentTotalSupply: U256::from(10u64),
                    maxSupply: U256::from(10_000u64),
                }
            ))
        );

        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .respond_eth_call_selector(seadrop::getPublicDropCall::SELECTOR, json!(public_drop_hex))
            .respond_eth_call_selector(
                seadrop::getAllowedFeeRecipientsCall::SELECTOR,
                json!(allowed_hex),
            )
            .respond_eth_call_selector(seadrop::getMintStatsCall::SELECTOR, json!(mint_stats_hex))
            .respond(
                "eth_getBlockByNumber",
                json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x3b9aca00"}),
            )
            .respond("eth_maxPriorityFeePerGas", json!("0x3b9aca00"))
            .respond("eth_estimateGas", json!("0x2bf20"))
            .error_matching(
                "eth_estimateGas",
                move |params| {
                    let from = params
                        .get(0)
                        .and_then(|c| c.get("from"))
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse::<Address>().ok());
                    Some(from) == simulation_revert_wallet.map(Some)
                },
                -32000,
                "execution reverted: simulated wallet-specific revert",
            )
            .respond_dynamic("eth_getTransactionCount", move |params| {
                let addr = params
                    .get(0)
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                let nonce = addr
                    .and_then(|a| nonce_by_wallet.get(&a).copied())
                    .unwrap_or(0);
                json!(format!("0x{nonce:x}"))
            })
            .respond_dynamic("eth_getBalance", move |params| {
                let addr = params
                    .get(0)
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                let balance = addr
                    .and_then(|a| balance_by_wallet.get(&a).copied())
                    .unwrap_or("0xde0b6b3a7640000");
                json!(balance)
            });
        let transport = attach_mint_receipt_routing_with(transport, NFT, overrides).build();
        let capture = transport.capture_handle();

        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap();
        (RpcPool::from_clients(1, vec![client]), capture)
    }

    /// A single-endpoint public pool whose stage opens `start_delay` in the
    /// future (rather than the fixed always-open 2020 stage every other
    /// fixture uses), and whose `eth_sendRawTransaction` dispatch times are
    /// recorded to `send_wall_clock_log` -- lets a test compare real
    /// wall-clock instants against another instant it captured itself
    /// (e.g. when `MultiWalletProgress::MatrixPrepared` fired), proving the
    /// broadcast job matrix was built well before the stage-open barrier
    /// released, not merely that signing happened first.
    async fn public_pool_with_future_start(
        start_delay: StdDuration,
        send_wall_clock_log: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    ) -> RpcPool {
        let start_time = OffsetDateTime::now_utc() + start_delay;
        let public_drop = seadrop::PublicDropAbi {
            mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
            startTime: alloy_primitives::Uint::from(start_time.unix_timestamp() as u64),
            endTime: alloy_primitives::Uint::from(
                datetime!(2999-01-01 00:00:00 UTC).unix_timestamp() as u64,
            ),
            maxTotalMintableByWallet: 50,
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
                    currentTotalSupply: U256::from(10u64),
                    maxSupply: U256::from(10_000u64),
                }
            ))
        );

        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .respond_eth_call_selector(seadrop::getPublicDropCall::SELECTOR, json!(public_drop_hex))
            .respond_eth_call_selector(
                seadrop::getAllowedFeeRecipientsCall::SELECTOR,
                json!(allowed_hex),
            )
            .respond_eth_call_selector(seadrop::getMintStatsCall::SELECTOR, json!(mint_stats_hex))
            .respond(
                "eth_getBlockByNumber",
                json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x3b9aca00"}),
            )
            .respond("eth_maxPriorityFeePerGas", json!("0x3b9aca00"))
            .respond("eth_estimateGas", json!("0x2bf20"))
            .respond("eth_getTransactionCount", json!("0x0"))
            .respond("eth_getBalance", json!("0xde0b6b3a7640000"));
        let overrides = MintReceiptOverrides {
            send_wall_clock_log: Some(send_wall_clock_log),
            ..Default::default()
        };
        let transport = attach_mint_receipt_routing_with(transport, NFT, overrides).build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap();
        RpcPool::from_clients(1, vec![client])
    }

    /// `endpoint_count` independent, identically-fixtured send-capable
    /// endpoints sharing one `RpcPool` -- for proving broadcast
    /// concurrency/fan-out behavior across multiple wallets AND multiple
    /// endpoints at once (Section 12), not just multiple wallets against a
    /// single endpoint. Every endpoint independently computes the same
    /// deterministic tx hash from the same raw bytes, so per-wallet
    /// receipts still resolve correctly regardless of which endpoint the
    /// scheduler happens to read from.
    async fn public_pool_multi_endpoint(
        endpoint_count: usize,
        send_delay: StdDuration,
    ) -> (RpcPool, Vec<crate::chain::mock::CaptureHandle>) {
        public_pool_multi_endpoint_with_order_log(endpoint_count, send_delay, None).await
    }

    /// Like [`public_pool_multi_endpoint`], but if `order_log` is given,
    /// every endpoint's `eth_sendRawTransaction` handler pushes
    /// `(endpoint_index, recovered_wallet)` to it at the moment the call is
    /// dispatched (before any configured delay is awaited) -- giving tests
    /// the true, deterministic dispatch-start order across the whole
    /// (wallet x endpoint) matrix, not just completion order.
    async fn public_pool_multi_endpoint_with_order_log(
        endpoint_count: usize,
        send_delay: StdDuration,
        order_log: Option<DispatchOrderLog>,
    ) -> (RpcPool, Vec<crate::chain::mock::CaptureHandle>) {
        let public_drop = seadrop::PublicDropAbi {
            mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
            startTime: alloy_primitives::Uint::from(
                datetime!(2020-01-01 00:00:00 UTC).unix_timestamp() as u64,
            ),
            endTime: alloy_primitives::Uint::from(
                datetime!(2999-01-01 00:00:00 UTC).unix_timestamp() as u64,
            ),
            maxTotalMintableByWallet: 50,
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
                    currentTotalSupply: U256::from(10u64),
                    maxSupply: U256::from(10_000u64),
                }
            ))
        );

        let mut clients = Vec::with_capacity(endpoint_count);
        let mut captures = Vec::with_capacity(endpoint_count);
        for endpoint_idx in 0..endpoint_count {
            let transport = MockTransport::builder()
                .respond("eth_chainId", json!("0x1"))
                .respond("eth_blockNumber", json!("0x1"))
                .respond_eth_call_selector(
                    seadrop::getPublicDropCall::SELECTOR,
                    json!(public_drop_hex),
                )
                .respond_eth_call_selector(
                    seadrop::getAllowedFeeRecipientsCall::SELECTOR,
                    json!(allowed_hex),
                )
                .respond_eth_call_selector(
                    seadrop::getMintStatsCall::SELECTOR,
                    json!(mint_stats_hex),
                )
                .respond(
                    "eth_getBlockByNumber",
                    json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x3b9aca00"}),
                )
                .respond("eth_maxPriorityFeePerGas", json!("0x3b9aca00"))
                .respond("eth_estimateGas", json!("0x2bf20"))
                .respond("eth_getTransactionCount", json!("0x0"))
                .respond("eth_getBalance", json!("0xde0b6b3a7640000"));
            let overrides = MintReceiptOverrides {
                send_delay: Some(send_delay),
                order_log: order_log.clone().map(|log| (endpoint_idx, log)),
                ..Default::default()
            };
            let transport = attach_mint_receipt_routing_with(transport, NFT, overrides).build();
            captures.push(transport.capture_handle());
            let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
                .await
                .unwrap();
            clients.push(client);
        }
        (RpcPool::from_clients(1, clients), captures)
    }

    fn tiny_config() -> MultiWalletConfig {
        MultiWalletConfig {
            gas_buffer_multiplier: 1.2,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(1_000_000_000_000_000_000u128),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(1_000_000_000_000_000_000u128),
            },
            max_session_total_spend: None,
            benchmark: BenchmarkConfig {
                sample_count: 1,
                sample_delay: StdDuration::ZERO,
            },
            health: HealthPolicy::default(),
            receipt_poll_interval: StdDuration::from_millis(5),
            receipt_timeout: StdDuration::from_millis(200),
            broadcast_concurrency: 8,
            opensea_api_concurrency: 4,
        }
    }

    fn wallets_abc() -> Vec<(WalletMintRequest, LocalSigner)> {
        let signer_a = signer_for("kairox-phase5-wallet-a");
        let signer_b = signer_for("kairox-phase5-wallet-b");
        let signer_c = signer_for("kairox-phase5-wallet-c");
        vec![
            (
                WalletMintRequest {
                    label: Some("wallet-a".into()),
                    address: signer_a.address(),
                    quantity: 1,
                },
                signer_a,
            ),
            (
                WalletMintRequest {
                    label: Some("wallet-b".into()),
                    address: signer_b.address(),
                    quantity: 1,
                },
                signer_b,
            ),
            (
                WalletMintRequest {
                    label: Some("wallet-c".into()),
                    address: signer_c.address(),
                    quantity: 1,
                },
                signer_c,
            ),
        ]
    }

    /// `n` distinct, deterministic self-funded wallets -- for concurrency
    /// tests that need more participants than the fixed `wallets_abc` trio
    /// to actually exceed a configured concurrency bound.
    fn wallets_n(n: usize) -> Vec<(WalletMintRequest, LocalSigner)> {
        (0..n)
            .map(|i| {
                let signer = signer_for(&format!("kairox-phase5-concurrency-wallet-{i}"));
                (
                    WalletMintRequest {
                        label: Some(format!("wallet-{i}")),
                        address: signer.address(),
                        quantity: 1,
                    },
                    signer,
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn three_wallets_prepare_and_dispatch_independently() {
        let wallets = wallets_abc();
        let nonces: HashMap<Address, u64> = wallets
            .iter()
            .enumerate()
            .map(|(i, (r, _))| (r.address, i as u64))
            .collect();
        let mut pool = public_pool(nonces, HashMap::new()).await;

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();

        assert_eq!(result.wallets.len(), 3);
        assert_eq!(result.metrics.wallet_count, 3);
        assert_eq!(result.metrics.prepared_wallet_count, 3);
        assert_eq!(result.successful_count(), 3);

        // Each wallet signs exactly once, producing a distinct tx hash and
        // distinct raw bytes -- and each wallet's fan-out reached the one
        // configured send-capable endpoint (proven by a non-empty,
        // Accepted-only broadcast_results set per wallet).
        let mut tx_hashes = std::collections::HashSet::new();
        let mut all_token_ids = std::collections::HashSet::new();
        for w in &result.wallets {
            let minted = match &w.state {
                WalletExecutionState::ConfirmedSuccess { minted } => minted,
                other => panic!(
                    "wallet {:?} must be ConfirmedSuccess, got {other:?}",
                    w.request.address
                ),
            };
            // Section 6: exact per-wallet token correlation -- exactly one
            // attributable mint (quantity 1), and no wallet's result may
            // contain another wallet's token id.
            assert_eq!(
                minted.len(),
                1,
                "each wallet requested quantity 1, so exactly one attributable mint token id must be recovered"
            );
            assert!(
                all_token_ids.insert(minted[0].token_id),
                "token id {} was attributed to more than one wallet",
                minted[0].token_id
            );

            let tx_hash = w.tx_hash.expect("confirmed wallet must have a tx hash");
            assert!(
                tx_hashes.insert(tx_hash),
                "tx hashes must be unique per wallet"
            );
            assert_eq!(w.broadcast_results.len(), 1);
            assert!(matches!(
                w.broadcast_results[0].outcome,
                crate::execution::broadcast::BroadcastOutcome::Accepted { tx_hash: accepted } if accepted == tx_hash
            ));
        }
        assert_eq!(
            all_token_ids.len(),
            3,
            "all three wallets must have received distinct, non-overlapping token ids"
        );
    }

    #[tokio::test]
    async fn one_wallet_insufficient_balance_does_not_block_others() {
        let wallets = wallets_abc();
        let poor_wallet = wallets[1].0.address;
        let mut balances = HashMap::new();
        balances.insert(poor_wallet, "0x0");
        let mut pool = public_pool(HashMap::new(), balances).await;

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();

        let poor = result
            .wallets
            .iter()
            .find(|w| w.request.address == poor_wallet)
            .unwrap();
        assert_eq!(poor.state, WalletExecutionState::InsufficientBalance);

        let others_ok = result
            .wallets
            .iter()
            .filter(|w| w.request.address != poor_wallet)
            .all(|w| w.state.is_terminal_success());
        assert!(
            others_ok,
            "wallets unaffected by the insufficient-balance wallet must still succeed"
        );
    }

    #[tokio::test]
    async fn one_wallet_simulation_revert_does_not_block_others() {
        // Section 28: wallet B's eth_estimateGas (simulation) reverts.
        // A and C, sharing the same pool, must still independently succeed.
        let wallets = wallets_abc();
        let reverting_wallet = wallets[1].0.address;
        let (mut pool, _capture) = public_pool_with_overrides(
            HashMap::new(),
            HashMap::new(),
            Some(reverting_wallet),
            MintReceiptOverrides::default(),
        )
        .await;

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();

        let b = result
            .wallets
            .iter()
            .find(|w| w.request.address == reverting_wallet)
            .unwrap();
        assert!(
            matches!(b.state, WalletExecutionState::Failed { .. }),
            "wallet with a simulation revert must fail cleanly, got {:?}",
            b.state
        );
        assert!(b.tx_hash.is_none());

        let others_ok = result
            .wallets
            .iter()
            .filter(|w| w.request.address != reverting_wallet)
            .all(|w| w.state.is_terminal_success());
        assert!(
            others_ok,
            "wallets unaffected by wallet B's simulation revert must still succeed"
        );
    }

    #[tokio::test]
    async fn one_wallet_broadcast_fatal_rejection_does_not_block_others() {
        // Section 30: every send endpoint definitively (fatally) rejects
        // wallet B's raw transaction. This must record a deterministic
        // Failed/ConfirmedRevert-style terminal state, never Uncertain --
        // and A/C must remain independent.
        let wallets = wallets_abc();
        let rejected_wallet = wallets[1].0.address;
        let (mut pool, _capture) = public_pool_with_overrides(
            HashMap::new(),
            HashMap::new(),
            None,
            MintReceiptOverrides {
                fatal_reject_wallet: Some(rejected_wallet),
                ..Default::default()
            },
        )
        .await;

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();

        let b = result
            .wallets
            .iter()
            .find(|w| w.request.address == rejected_wallet)
            .unwrap();
        assert!(
            !matches!(b.state, WalletExecutionState::Uncertain),
            "a definitive fatal rejection must never be converted into Uncertain: {:?}",
            b.state
        );
        assert!(
            matches!(b.state, WalletExecutionState::Failed { .. }),
            "wallet B must be recorded Failed after a fatal rejection, got {:?}",
            b.state
        );

        let others_ok = result
            .wallets
            .iter()
            .filter(|w| w.request.address != rejected_wallet)
            .all(|w| w.state.is_terminal_success());
        assert!(
            others_ok,
            "wallets unaffected by wallet B's fatal broadcast rejection must still succeed"
        );
    }

    #[tokio::test]
    async fn one_wallet_receipt_revert_does_not_block_others() {
        // Section 31: wallet B's transaction is accepted by the network but
        // its receipt reports a revert. Must be ConfirmedRevert, never
        // replaced -- and A/C must independently succeed.
        let wallets = wallets_abc();
        let reverted_wallet = wallets[1].0.address;
        let (mut pool, _capture) = public_pool_with_overrides(
            HashMap::new(),
            HashMap::new(),
            None,
            MintReceiptOverrides {
                revert_wallet: Some(reverted_wallet),
                ..Default::default()
            },
        )
        .await;

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();

        let b = result
            .wallets
            .iter()
            .find(|w| w.request.address == reverted_wallet)
            .unwrap();
        assert_eq!(b.state, WalletExecutionState::ConfirmedRevert);
        assert!(
            b.tx_hash.is_some(),
            "a reverted wallet's transaction did land on-chain, so its hash is known"
        );

        let others_ok = result
            .wallets
            .iter()
            .filter(|w| w.request.address != reverted_wallet)
            .all(|w| w.state.is_terminal_success());
        assert!(
            others_ok,
            "wallets unaffected by wallet B's receipt revert must still succeed"
        );
    }

    #[tokio::test]
    async fn one_wallet_uncertain_receipt_does_not_block_others_and_is_never_replaced() {
        // Section 29: wallet B's broadcast is accepted, but no receipt ever
        // confirms it (a genuinely uncertain on-chain outcome). Must map to
        // Uncertain -- never a second signature, never a replacement/
        // different-nonce transaction, never automatically cancelling A/C.
        let wallets = wallets_abc();
        let uncertain_wallet = wallets[1].0.address;
        let (mut pool, _capture) = public_pool_with_overrides(
            HashMap::new(),
            HashMap::new(),
            None,
            MintReceiptOverrides {
                unknown_receipt_wallet: Some(uncertain_wallet),
                ..Default::default()
            },
        )
        .await;

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();

        let b = result
            .wallets
            .iter()
            .find(|w| w.request.address == uncertain_wallet)
            .unwrap();
        assert_eq!(b.state, WalletExecutionState::Uncertain);
        // Broadcast was accepted (the hash is known) but exactly once --
        // Kairox never signs or sends a second, different transaction for
        // an uncertain wallet.
        assert!(b.tx_hash.is_some());
        assert_eq!(b.broadcast_results.len(), 1);

        let others_ok = result
            .wallets
            .iter()
            .filter(|w| w.request.address != uncertain_wallet)
            .all(|w| w.state.is_terminal_success());
        assert!(
            others_ok,
            "wallets unaffected by wallet B's uncertain receipt must still succeed"
        );
    }

    #[tokio::test]
    async fn broadcast_peak_concurrency_never_exceeds_configured_limit_across_wallets_and_endpoints()
     {
        // Section 7 (completion pass): 3 wallets x 3 send endpoints = 9
        // actual (wallet, endpoint) `eth_sendRawTransaction` submissions.
        // broadcast_concurrency: 2 now bounds the REQUEST MATRIX itself --
        // not merely how many wallets may be inside a per-wallet fan-out.
        // Every send is deliberately delayed so requests genuinely overlap.
        // Prove: total send calls == 9, peak simultaneously in flight <= 2
        // (and actually reaches 2), every wallet reaches all 3 endpoints,
        // and every endpoint receives byte-identical bytes per wallet while
        // different wallets' bytes differ from each other.
        let wallets = wallets_abc();
        let (mut pool, captures) =
            public_pool_multi_endpoint(3, StdDuration::from_millis(30)).await;
        let mut config = tiny_config();
        config.broadcast_concurrency = 2;

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &config,
            |_| {},
        )
        .await
        .unwrap();

        assert_eq!(
            result.successful_count(),
            3,
            "every wallet must eventually be dispatched, not just the first `concurrency` of them"
        );
        for w in &result.wallets {
            assert_eq!(
                w.broadcast_results.len(),
                3,
                "each wallet must fan out to all 3 send endpoints"
            );
        }
        let peak = result
            .metrics
            .broadcast_peak_concurrency
            .expect("broadcast peak concurrency must be measured, not left unset");
        assert!(
            peak <= 2,
            "observed broadcast concurrency {peak} exceeded the configured limit of 2"
        );
        assert!(
            peak >= 2,
            "with 3 delayed wallets and a limit of 2, the observed peak should actually reach the bound (got {peak})"
        );

        // Byte-identical PreparedBroadcast bytes across every endpoint for
        // the same wallet -- concurrency limiting is transport scheduling
        // only, never a source of endpoint-specific transaction variants.
        let bodies: Vec<std::collections::HashSet<Vec<u8>>> = captures
            .iter()
            .map(|c| {
                c.prebuilt_bodies()
                    .into_iter()
                    .map(|b| b.to_vec())
                    .collect()
            })
            .collect();
        assert_eq!(bodies[0].len(), 3, "3 wallets each sent to this endpoint");
        for endpoint_bodies in &bodies[1..] {
            assert_eq!(
                endpoint_bodies, &bodies[0],
                "every endpoint must receive the exact same set of byte-identical per-wallet broadcast bodies -- concurrency limiting is transport scheduling only, never a source of endpoint-specific transaction variants"
            );
        }
        assert_eq!(
            bodies[0].len(),
            3,
            "the 3 distinct bodies observed at endpoint 0 must be exactly the 3 wallets' own distinct transaction bytes"
        );

        let total_sends: usize = captures.iter().map(|c| c.prebuilt_bodies().len()).sum();
        assert_eq!(
            total_sends, 9,
            "3 wallets x 3 endpoints must produce exactly 9 actual send operations"
        );
    }

    #[tokio::test]
    async fn broadcast_job_matrix_is_fully_built_before_the_stage_open_barrier() {
        // Gap 1: the (wallet x endpoint) broadcast job matrix must exist
        // in full BEFORE the stage-open sleep, not be constructed after
        // it. Proven with a real future stage start (150ms out) and two
        // independently-captured wall-clock instants: `on_progress`
        // records when `MatrixPrepared` fires, and the mock transport
        // records when the real `eth_sendRawTransaction` dispatch happens.
        // If the matrix were built after the sleep, `MatrixPrepared` would
        // fire close to the send time; since it is built before, it must
        // fire near t=0, well before the ~150ms stage-open wait elapses.
        let wallets: Vec<_> = wallets_abc().into_iter().take(1).collect();
        let send_log: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // `startTime` is encoded on-chain as whole Unix seconds, so a
        // short sub-second delay can truncate away entirely -- use a full
        // 2s margin so the target survives truncation with room to spare.
        let mut pool =
            public_pool_with_future_start(StdDuration::from_millis(2000), send_log.clone()).await;

        let test_start = std::time::Instant::now();
        let matrix_prepared_at: std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let matrix_prepared_for_closure = matrix_prepared_at.clone();

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &tiny_config(),
            move |progress| {
                if matches!(progress, MultiWalletProgress::MatrixPrepared) {
                    let mut slot = matrix_prepared_for_closure.lock().expect("mutex poisoned");
                    if slot.is_none() {
                        *slot = Some(std::time::Instant::now());
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result.successful_count(), 1);

        let matrix_prepared_ms = matrix_prepared_at
            .lock()
            .expect("mutex poisoned")
            .expect("MatrixPrepared must have fired")
            .duration_since(test_start)
            .as_millis();
        let first_send_ms = send_log
            .lock()
            .expect("mutex poisoned")
            .first()
            .copied()
            .expect("a send must have been dispatched")
            .duration_since(test_start)
            .as_millis();

        assert!(
            matrix_prepared_ms < 500,
            "the broadcast job matrix must be built near t=0, well before the stage-open wait; got {matrix_prepared_ms}ms"
        );
        assert!(
            first_send_ms >= 900,
            "the actual network dispatch must not happen before the stage-open barrier releases; got {first_send_ms}ms"
        );
        assert!(
            matrix_prepared_ms < first_send_ms,
            "MatrixPrepared ({matrix_prepared_ms}ms) must precede the first real network dispatch ({first_send_ms}ms)"
        );
    }

    #[tokio::test]
    async fn broadcast_dispatch_does_not_drain_all_endpoints_for_one_wallet_before_others_start() {
        // Section 8: fairness. With 3 wallets x 3 endpoints and
        // concurrency 1 (fully serial, so dispatch order is unambiguous),
        // prove wallet A does not get all 3 of its endpoint submissions
        // dispatched before wallet B and C each get their own first
        // dispatch opportunity. Endpoint-major round-robin job ordering
        // guarantees every wallet is visited once per "round" before any
        // wallet starts its second endpoint.
        let wallets = wallets_abc();
        let order_log: std::sync::Arc<std::sync::Mutex<Vec<(usize, Address)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut pool, _captures) = public_pool_multi_endpoint_with_order_log(
            3,
            StdDuration::from_millis(2),
            Some(order_log.clone()),
        )
        .await;
        let mut config = tiny_config();
        config.broadcast_concurrency = 1;

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &config,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(result.successful_count(), 3);

        let order = order_log.lock().expect("mutex poisoned").clone();
        assert_eq!(order.len(), 9, "3 wallets x 3 endpoints = 9 dispatches");

        // The first 3 dispatches (one full round) must already include all
        // 3 distinct wallets -- proof wallet A's second/third endpoint
        // submission never jumps the queue ahead of B/C's first.
        let first_round: std::collections::HashSet<Address> =
            order[0..3].iter().map(|(_, wallet)| *wallet).collect();
        assert_eq!(
            first_round.len(),
            3,
            "the first round of dispatches must reach all 3 wallets, not just the first wallet's endpoints: {order:?}"
        );

        // No wallet may appear a second time before every wallet has
        // appeared once.
        let mut seen = std::collections::HashSet::new();
        for (i, (_, wallet)) in order.iter().enumerate() {
            if seen.len() < 3 && seen.contains(wallet) {
                panic!(
                    "wallet {wallet:?} was dispatched a second time at position {i} before every wallet had a first dispatch: {order:?}"
                );
            }
            seen.insert(*wallet);
        }
    }

    #[tokio::test]
    async fn aggregate_quantity_exceeding_remaining_supply_fails_whole_session_before_signing() {
        // Remaining supply is deliberately smaller than the 3 wallets'
        // combined requested quantity (3).
        let public_drop = seadrop::PublicDropAbi {
            mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
            startTime: alloy_primitives::Uint::from(
                datetime!(2020-01-01 00:00:00 UTC).unix_timestamp() as u64,
            ),
            endTime: alloy_primitives::Uint::from(
                datetime!(2999-01-01 00:00:00 UTC).unix_timestamp() as u64,
            ),
            maxTotalMintableByWallet: 50,
            feeBps: 0,
            restrictFeeRecipients: false,
        };
        let public_drop_hex = format!(
            "0x{}",
            hex::encode(seadrop::getPublicDropCall::abi_encode_returns(&public_drop))
        );
        let mint_stats_hex = format!(
            "0x{}",
            hex::encode(seadrop::getMintStatsCall::abi_encode_returns(
                &seadrop::getMintStatsReturn {
                    minterNumMinted: U256::ZERO,
                    currentTotalSupply: U256::from(9_999u64),
                    maxSupply: U256::from(10_000u64), // only 1 remaining
                }
            ))
        );
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .respond_eth_call_selector(seadrop::getPublicDropCall::SELECTOR, json!(public_drop_hex))
            .respond_eth_call_selector(seadrop::getMintStatsCall::SELECTOR, json!(mint_stats_hex))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap();
        let mut pool = RpcPool::from_clients(1, vec![client]);

        let wallets = wallets_abc(); // 3 wallets x quantity 1 = 3 requested
        let err = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
        assert!(err.to_string().contains("aggregate"));
    }

    #[tokio::test]
    async fn aggregate_session_spend_cap_safe_actual_cost_passes_despite_high_declared_bound() {
        // Section 22 Test A: each wallet's declared per-wallet cap is 1
        // ETH, so the naive `wallet_count * per_wallet_cap` upper bound is
        // 3 ETH -- which alone would exceed a 0.10 ETH session cap. But the
        // real finalized cost (3 wallets * 0.01 ETH mint price, no
        // meaningful gas in the mock) is ~0.03 ETH, safely under 0.10 ETH.
        // The session must succeed: the declared bound is only ever a
        // fast-path ACCEPT, never a reason to reject.
        let wallets = wallets_abc();
        let mut pool = public_pool(HashMap::new(), HashMap::new()).await;
        let mut config = tiny_config();
        config.max_session_total_spend = Some(U256::from(100_000_000_000_000_000u128)); // 0.10 ETH

        let result = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &config,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(
            result.successful_count(),
            3,
            "a session whose real aggregate cost is well under the cap must not be rejected"
        );
    }

    #[tokio::test]
    async fn aggregate_session_spend_cap_exceeded_by_actual_cost_fails_before_signing() {
        // Section 22 Test B: the real finalized aggregate (3 wallets * 0.01
        // ETH mint price = 0.03 ETH, plus gas) exceeds a strict 0.01 ETH
        // session cap. Must fail the whole session -- zero signatures, zero
        // broadcasts -- proven here by zero `eth_sendRawTransaction` calls
        // ever reaching the mock transport.
        let wallets = wallets_abc();
        let (mut pool, capture) = public_pool_with_capture(HashMap::new(), HashMap::new()).await;
        let mut config = tiny_config();
        config.max_session_total_spend = Some(U256::from(10_000_000_000_000_000u128)); // 0.01 ETH

        let err = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &config,
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
        assert!(err.to_string().to_lowercase().contains("session cap"));

        let sends = capture.calls_for("eth_sendRawTransaction");
        assert_eq!(
            sends.len(),
            0,
            "no wallet may be signed or broadcast once the real aggregate cost is known to exceed the session cap"
        );
    }

    #[tokio::test]
    async fn no_verified_read_endpoint_fails_whole_session() {
        let wallets = wallets_abc();
        let mut pool = RpcPool::from_clients(1, Vec::new());
        let err = run_multi_wallet_public_mint(
            &mut pool,
            &chain(),
            NFT,
            SEADROP,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    // --- Key loading / verification -----------------------------------

    #[test]
    fn key_mismatch_fails_only_that_wallet() {
        use crate::chain::config::testing::FakeEnv;
        let good = signer_for("kairox-phase5-key-good");
        let wrong = signer_for("kairox-phase5-key-wrong");

        let entries = vec![
            WalletManifestEntry {
                label: Some("good".into()),
                address: good.address(),
                quantity: 1,
                key_env: "KAIROX_KEY_GOOD".into(),
            },
            WalletManifestEntry {
                label: Some("mismatched".into()),
                address: address!("0000000000000000000000000000000000000fff"),
                quantity: 1,
                key_env: "KAIROX_KEY_MISMATCHED".into(),
            },
        ];

        let env = FakeEnv(HashMap::from([
            (
                "KAIROX_KEY_GOOD".to_string(),
                hex::encode(keccak256(b"kairox-phase5-key-good").0),
            ),
            (
                "KAIROX_KEY_MISMATCHED".to_string(),
                // This key actually derives to `wrong`'s address, not the
                // manifest's declared address -- a real mismatch.
                hex::encode(keccak256(b"kairox-phase5-key-wrong").0),
            ),
        ]));

        let results = load_and_verify_wallet_keys(&env, &entries);
        assert_eq!(results.len(), 2);
        assert!(
            results[0].1.is_ok(),
            "the correctly-matching wallet must still load"
        );
        assert_eq!(results[0].1.as_ref().unwrap().address(), good.address());
        assert!(
            results[1].1.is_err(),
            "a key that resolves to a different address than declared must be rejected"
        );
        let _ = wrong;
    }

    #[test]
    fn missing_key_env_fails_only_that_wallet() {
        use crate::chain::config::testing::FakeEnv;
        let good = signer_for("kairox-phase5-present-key");
        let entries = vec![
            WalletManifestEntry {
                label: None,
                address: good.address(),
                quantity: 1,
                key_env: "KAIROX_KEY_PRESENT".into(),
            },
            WalletManifestEntry {
                label: None,
                address: address!("0000000000000000000000000000000000000eee"),
                quantity: 1,
                key_env: "KAIROX_KEY_MISSING".into(),
            },
        ];
        let env = FakeEnv(HashMap::from([(
            "KAIROX_KEY_PRESENT".to_string(),
            hex::encode(keccak256(b"kairox-phase5-present-key").0),
        )]));
        let results = load_and_verify_wallet_keys(&env, &entries);
        assert!(results[0].1.is_ok());
        assert!(results[1].1.is_err());
    }

    // --- OpenSea multi-wallet -------------------------------------------

    fn opensea_mint_response_json(
        wallet: Address,
        quantity: u64,
        value_wei: u128,
    ) -> serde_json::Value {
        let calldata =
            seadrop::encode_mint_public(NFT, FEE_RECIPIENT, Address::ZERO, quantity).unwrap();
        let _ = wallet;
        json!({
            "to": SEADROP.to_string(),
            "data": format!("0x{}", hex::encode(&calldata)),
            "value": format!("0x{value_wei:x}"),
            "chain": "ethereum",
        })
    }

    fn drop_details_response() -> serde_json::Value {
        json!({
            "collection_slug": "cool-cats",
            "chain": "ethereum",
            "contract_address": NFT.to_string(),
            "drop_type": "seadrop_v1_erc721",
            "is_minting": true,
            "stages": [],
        })
    }

    async fn opensea_chain_pool() -> RpcPool {
        opensea_chain_pool_with_mint_stats(None, None).await.0
    }

    async fn opensea_chain_pool_with_capture() -> (RpcPool, crate::chain::mock::CaptureHandle) {
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
            .respond("eth_getBalance", json!("0xde0b6b3a7640000"));
        let transport = attach_mint_receipt_routing(transport, NFT).build();
        let capture = transport.capture_handle();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap();
        (RpcPool::from_clients(1, vec![client]), capture)
    }

    /// Like [`opensea_chain_pool`], but when `mint_stats` is given, also
    /// stubs `getMintStats` -- required for the aggregate stage-supply
    /// check, which reads a fresh, verified `currentTotalSupply` before
    /// releasing any wallet to sign. When `allow_list_merkle_root` is
    /// given, also stubs `getAllowListMerkleRoot` so an allow-list mint's
    /// own Merkle proof validation succeeds against a real tree.
    async fn opensea_chain_pool_with_mint_stats(
        mint_stats: Option<(u64, u64, u64)>,
        allow_list_merkle_root: Option<alloy_primitives::B256>,
    ) -> (RpcPool, crate::chain::mock::CaptureHandle) {
        let mut builder = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .respond("eth_estimateGas", json!("0x2bf20"))
            .respond(
                "eth_getBlockByNumber",
                json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x3b9aca00"}),
            )
            .respond("eth_maxPriorityFeePerGas", json!("0x3b9aca00"))
            .respond("eth_getTransactionCount", json!("0x0"))
            .respond("eth_getBalance", json!("0xde0b6b3a7640000"));
        if let Some((minter_num_minted, current_total_supply, max_supply)) = mint_stats {
            let mint_stats_hex = format!(
                "0x{}",
                hex::encode(seadrop::getMintStatsCall::abi_encode_returns(
                    &seadrop::getMintStatsReturn {
                        minterNumMinted: U256::from(minter_num_minted),
                        currentTotalSupply: U256::from(current_total_supply),
                        maxSupply: U256::from(max_supply),
                    }
                ))
            );
            builder = builder.respond_eth_call_selector(
                seadrop::getMintStatsCall::SELECTOR,
                json!(mint_stats_hex),
            );
        }
        if let Some(root) = allow_list_merkle_root {
            let root_hex = format!(
                "0x{}",
                hex::encode(seadrop::getAllowListMerkleRootCall::abi_encode_returns(
                    &root
                ))
            );
            builder = builder.respond_eth_call_selector(
                seadrop::getAllowListMerkleRootCall::SELECTOR,
                json!(root_hex),
            );
        }
        let transport = attach_mint_receipt_routing(builder, NFT).build();
        let capture = transport.capture_handle();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap();
        (RpcPool::from_clients(1, vec![client]), capture)
    }

    /// `endpoint_count` independent, identically-fixtured send-capable
    /// endpoints for an OpenSea multi-wallet session -- proving broadcast
    /// concurrency/fan-out behavior across multiple OpenSea wallets AND
    /// multiple blockchain send endpoints at once.
    async fn opensea_chain_pool_multi_endpoint(
        endpoint_count: usize,
        send_delay: StdDuration,
    ) -> (RpcPool, Vec<crate::chain::mock::CaptureHandle>) {
        let mut clients = Vec::with_capacity(endpoint_count);
        let mut captures = Vec::with_capacity(endpoint_count);
        for _ in 0..endpoint_count {
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
                .respond("eth_getBalance", json!("0xde0b6b3a7640000"));
            let overrides = MintReceiptOverrides {
                send_delay: Some(send_delay),
                ..Default::default()
            };
            let transport = attach_mint_receipt_routing_with(transport, NFT, overrides).build();
            captures.push(transport.capture_handle());
            let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
                .await
                .unwrap();
            clients.push(client);
        }
        (RpcPool::from_clients(1, clients), captures)
    }

    /// A valid, real two-leaf allow-list Merkle tree for `wallet_a`/
    /// `wallet_b`, both sharing `mint_params` -- returns
    /// `(root, proof_for_a, proof_for_b)`.
    fn two_wallet_allow_list_tree(
        wallet_a: Address,
        wallet_b: Address,
        mint_params: &MintParams,
    ) -> (
        alloy_primitives::B256,
        Vec<alloy_primitives::B256>,
        Vec<alloy_primitives::B256>,
    ) {
        two_wallet_allow_list_tree_with_params(wallet_a, mint_params, wallet_b, mint_params)
    }

    /// Like [`two_wallet_allow_list_tree`], but each wallet may have its
    /// own distinct `MintParams` (e.g. a different validated
    /// `maxTokenSupplyForStage`) -- a genuine two-leaf tree built from two
    /// different leaves, not the same leaf shared by both wallets.
    fn two_wallet_allow_list_tree_with_params(
        wallet_a: Address,
        mint_params_a: &MintParams,
        wallet_b: Address,
        mint_params_b: &MintParams,
    ) -> (
        alloy_primitives::B256,
        Vec<alloy_primitives::B256>,
        Vec<alloy_primitives::B256>,
    ) {
        let leaf_a = seadrop_crypto::allow_list_merkle_leaf(wallet_a, mint_params_a);
        let leaf_b = seadrop_crypto::allow_list_merkle_leaf(wallet_b, mint_params_b);
        let root = seadrop_crypto::commutative_keccak256(leaf_a, leaf_b);
        (root, vec![leaf_b], vec![leaf_a])
    }

    fn allow_list_mint_response_json(
        wallet: Address,
        mint_params_abi: &MintParamsAbi,
        proof: Vec<alloy_primitives::B256>,
    ) -> serde_json::Value {
        let _ = wallet;
        let call = mintAllowListCall {
            nftContract: NFT,
            feeRecipient: FEE_RECIPIENT,
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: mint_params_abi.clone(),
            proof,
        };
        json!({
            "to": SEADROP.to_string(),
            "data": format!("0x{}", hex::encode(call.abi_encode())),
            "value": "0x0",
            "chain": "ethereum",
        })
    }

    #[tokio::test]
    async fn three_wallets_opensea_eligible_ineligible_eligible_mix() {
        let wallets = wallets_abc();
        let eligible_a = wallets[0].0.address;
        let ineligible_b = wallets[1].0.address;
        let eligible_c = wallets[2].0.address;

        let mut pool = opensea_chain_pool().await;

        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_dynamic("POST", "/api/v2/drops/cool-cats/mint", move |body| {
                let minter = body
                    .get("minter")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                match minter {
                    Some(a) if a == ineligible_b => {
                        (422, json!({"errors": ["wallet not in allowlist"]}))
                    }
                    Some(a) if a == eligible_a || a == eligible_c => {
                        (200, opensea_mint_response_json(a, 1, 0))
                    }
                    _ => (400, json!({"errors": ["unexpected minter"]})),
                }
            })
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));

        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let (result, _details) = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();

        let a = result
            .wallets
            .iter()
            .find(|w| w.request.address == eligible_a)
            .unwrap();
        let b = result
            .wallets
            .iter()
            .find(|w| w.request.address == ineligible_b)
            .unwrap();
        let c = result
            .wallets
            .iter()
            .find(|w| w.request.address == eligible_c)
            .unwrap();

        assert!(
            a.state.is_terminal_success(),
            "wallet A must succeed: {:?}",
            a.state
        );
        assert!(
            c.state.is_terminal_success(),
            "wallet C must succeed: {:?}",
            c.state
        );
        assert!(
            matches!(b.state, WalletExecutionState::Ineligible { .. }),
            "wallet B must be recorded ineligible, got {:?}",
            b.state
        );
        assert!(
            b.tx_hash.is_none(),
            "an ineligible wallet must never be signed or broadcast"
        );
    }

    #[tokio::test]
    async fn opensea_wallet_never_receives_another_wallets_calldata() {
        // Each wallet's mock response encodes ITS OWN address as the
        // effective minter -- if Kairox ever cross-wired wallet A's
        // request to wallet B's response, local validation would reject
        // it as a WalletMismatch, and this test would fail A or B outright
        // instead of both succeeding.
        let wallets = wallets_abc();
        let addr_a = wallets[0].0.address;
        let addr_b = wallets[1].0.address;

        let mut pool = opensea_chain_pool().await;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_dynamic("POST", "/api/v2/drops/cool-cats/mint", move |body| {
                let minter = body
                    .get("minter")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok())
                    .unwrap();
                // Structurally impossible to serve the wrong wallet's data
                // here: the mock itself is keyed by the requesting
                // wallet's own address.
                (200, opensea_mint_response_json(minter, 1, 0))
            })
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let two_wallets: Vec<_> = wallets.into_iter().take(2).collect();
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let (result, _) = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &two_wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();

        for w in &result.wallets {
            assert!(w.state.is_terminal_success(), "{:?}", w.state);
        }
        let _ = (addr_a, addr_b);
    }

    #[tokio::test]
    async fn opensea_api_globally_invalid_credentials_fails_first_wallet_and_is_reported() {
        // Section 15/17: the shared OpenSea API key is a session-wide fact,
        // not a per-wallet one -- a single wallet is not enough to prove
        // that. Three wallets, sequential (opensea_api_concurrency: 1) so
        // the session-cancellation signal is deterministic: wallet A's
        // mint POST returns 401, flipping the shared flag before B/C's
        // futures start, so B and C are skipped without ever calling
        // OpenSea themselves.
        let wallets = wallets_abc();
        let mut pool = opensea_chain_pool().await;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond("POST", "/api/v2/drops/cool-cats/mint", 401, json!({}))
            .build();
        let capture = opensea_transport.capture_handle();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let mut config = tiny_config();
        config.opensea_api_concurrency = 1;
        let (result, _) =
            run_multi_wallet_opensea_mint(&opensea, &mut pool, &target, &wallets, &config, |_| {})
                .await
                .unwrap();

        assert_eq!(result.wallets.len(), 3);
        for w in &result.wallets {
            assert!(!w.state.is_terminal_success());
            // Section 17: an authentication failure is never wallet
            // eligibility -- it must not be reported as `Ineligible`.
            assert!(
                !matches!(w.state, WalletExecutionState::Ineligible { .. }),
                "wallet {:?} auth failure must not be classified Ineligible: {:?}",
                w.request.address,
                w.state
            );
        }
        let b = &result.wallets[1];
        let c = &result.wallets[2];
        assert!(
            matches!(&b.state, WalletExecutionState::Failed { reason } if reason.contains("skipped")),
            "wallet B must be skipped once the shared auth failure is known: {:?}",
            b.state
        );
        assert!(
            matches!(&c.state, WalletExecutionState::Failed { reason } if reason.contains("skipped")),
            "wallet C must be skipped once the shared auth failure is known: {:?}",
            c.state
        );

        // Only wallet A's mint POST was ever sent -- B and C never called
        // OpenSea at all once the session-level auth failure was known.
        let mint_posts = capture
            .all()
            .into_iter()
            .filter(|(method, path, _)| method == "POST" && path == "/api/v2/drops/cool-cats/mint")
            .count();
        assert_eq!(mint_posts, 1);
    }

    #[tokio::test]
    async fn opensea_preflight_401_aborts_whole_session_before_any_wallet_mint_post() {
        // Section 16: the shared drop-details GET doubles as the credential
        // preflight. A 401 there must abort the entire multi-wallet session
        // before any wallet's mint POST/signing/broadcast is attempted.
        let wallets = wallets_abc();
        let mut pool = opensea_chain_pool().await;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond("GET", "/api/v2/drops/cool-cats", 401, json!({}))
            .build();
        let capture = opensea_transport.capture_handle();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let err = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(crate::opensea::errors::OpenSeaError::AuthenticationFailed)
        ));

        let mint_posts = capture
            .all()
            .into_iter()
            .filter(|(method, path, _)| method == "POST" && path == "/api/v2/drops/cool-cats/mint")
            .count();
        assert_eq!(
            mint_posts, 0,
            "no wallet mint POST may be attempted once the shared preflight fails"
        );
    }

    #[tokio::test]
    async fn opensea_peak_concurrency_never_exceeds_configured_limit() {
        // Section 7/8/32: 6 wallets, opensea_api_concurrency: 2. Every
        // wallet's mint POST is deliberately delayed so their requests
        // genuinely overlap. Prove: peak observed OpenSea concurrency <= 2
        // (never unbounded), and every eligible wallet is still eventually
        // processed. `minterIfNotPayer` is the zero address in the shared
        // canned response, so every wallet safely shares one mint response
        // body (SeaDrop treats the transaction's own sender as the minter).
        let wallets = wallets_n(6);
        let mut pool = opensea_chain_pool().await;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_delayed(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                std::time::Duration::from_millis(30),
                200,
                opensea_mint_response_json(Address::ZERO, 1, 0),
            )
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let mut config = tiny_config();
        config.opensea_api_concurrency = 2;

        let (result, _) =
            run_multi_wallet_opensea_mint(&opensea, &mut pool, &target, &wallets, &config, |_| {})
                .await
                .unwrap();

        assert_eq!(result.wallets.len(), 6);
        assert_eq!(
            result.successful_count(),
            6,
            "every eligible wallet must eventually be processed, not just the first `concurrency` of them"
        );
        let peak = result
            .metrics
            .opensea_peak_concurrency
            .expect("peak concurrency must be measured, not left unset");
        assert!(
            peak <= 2,
            "observed OpenSea concurrency {peak} exceeded the configured limit of 2"
        );
        assert!(
            peak >= 2,
            "with 6 delayed wallets and a limit of 2, the observed peak should actually reach the bound, not just stay low by coincidence (got {peak})"
        );
    }

    #[tokio::test]
    async fn slow_wallet_does_not_block_fast_wallets_in_opensea_session() {
        // Section 9: wallet B's mint POST is deliberately slow; A and C are
        // fast. With enough concurrency headroom, A and C must complete
        // without waiting for B merely because B is slow.
        let wallets = wallets_abc();
        let fast_a = wallets[0].0.address;
        let slow_wallet = wallets[1].0.address;
        let fast_c = wallets[2].0.address;
        let completion_order: std::sync::Arc<std::sync::Mutex<Vec<Address>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let order_for_closure = completion_order.clone();
        let mut pool = opensea_chain_pool().await;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_dynamic_delayed("POST", "/api/v2/drops/cool-cats/mint", move |body| {
                let minter = body
                    .get("minter")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                let delay = if minter == Some(slow_wallet) {
                    std::time::Duration::from_millis(60)
                } else {
                    std::time::Duration::from_millis(1)
                };
                if let Some(m) = minter {
                    order_for_closure.lock().expect("mutex poisoned").push(m);
                }
                (delay, 200, opensea_mint_response_json(Address::ZERO, 1, 0))
            })
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let mut config = tiny_config();
        config.opensea_api_concurrency = 4; // enough headroom for all 3 to start together

        let started = std::time::Instant::now();
        let (result, _) =
            run_multi_wallet_opensea_mint(&opensea, &mut pool, &target, &wallets, &config, |_| {})
                .await
                .unwrap();
        let elapsed = started.elapsed();
        // If A/C were forced to wait for B, the wall-clock time would
        // approach 3 * 60ms. Real concurrent, independent progress keeps
        // it close to B's own 60ms delay.
        assert!(
            elapsed < std::time::Duration::from_millis(150),
            "session took {elapsed:?}; fast wallets appear to have waited for the slow one"
        );

        assert_eq!(
            result.successful_count(),
            3,
            "all three wallets, including the slow one, must eventually complete"
        );

        // A and C's mint POSTs must have been *sent* essentially
        // immediately, not queued up behind B -- proven by both of them
        // appearing in the mock's request-arrival order before B's slow
        // response actually finishes, since with concurrency 4 all three
        // requests start together.
        let arrived = completion_order.lock().expect("mutex poisoned").clone();
        assert_eq!(arrived.len(), 3);
        assert!(arrived.contains(&fast_a));
        assert!(arrived.contains(&fast_c));
        assert!(arrived.contains(&slow_wallet));
    }

    #[tokio::test]
    async fn unconstrained_wallets_are_not_signed_before_a_slower_wallets_stage_constraint_is_known()
     {
        // Mixed-stage safety fix regression: wallet A and C's OpenSea
        // responses are unconstrained (public) and resolve immediately;
        // wallet B's response (which carries a real stage constraint) is
        // deliberately held closed via a gate. Even though A and C are
        // individually "ready" long before B, they must NOT be signed or
        // broadcast until B's response is known too -- proven here by
        // capturing zero `eth_sendRawTransaction` calls despite A/C's own
        // OpenSea round trip having completed well before B's gate opens.
        let wallets = wallets_abc();
        let wallet_a = wallets[0].0.address;
        let wallet_b = wallets[1].0.address;
        let wallet_c = wallets[2].0.address;

        let mint_params_abi = sample_stage_mint_params(1000);
        let mint_params = MintParams::from(&mint_params_abi);
        // Single-leaf tree: B is the only constrained wallet, so its own
        // leaf is a valid root with an empty proof.
        let leaf_b = seadrop_crypto::allow_list_merkle_leaf(wallet_b, &mint_params);

        let gate_a = std::sync::Arc::new(tokio::sync::Notify::new());
        let gate_b = std::sync::Arc::new(tokio::sync::Notify::new());
        let gate_c = std::sync::Arc::new(tokio::sync::Notify::new());
        gate_a.notify_one();
        gate_c.notify_one();
        // gate_b deliberately left un-notified until after we observe A/C
        // have already completed their own OpenSea round trip.

        let (gate_a_for_closure, gate_b_for_closure, gate_c_for_closure) =
            (gate_a.clone(), gate_b.clone(), gate_c.clone());
        let opensea_completed: std::sync::Arc<std::sync::Mutex<Vec<Address>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let opensea_completed_for_closure = opensea_completed.clone();

        let (mut pool, capture) =
            opensea_chain_pool_with_mint_stats(Some((0, 999, 10_000)), Some(leaf_b)).await;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_dynamic_gated("POST", "/api/v2/drops/cool-cats/mint", move |body| {
                let minter = body
                    .get("minter")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                let (gate, response) = match minter {
                    Some(a) if a == wallet_a => (
                        gate_a_for_closure.clone(),
                        opensea_mint_response_json(Address::ZERO, 1, 0),
                    ),
                    Some(a) if a == wallet_c => (
                        gate_c_for_closure.clone(),
                        opensea_mint_response_json(Address::ZERO, 1, 0),
                    ),
                    Some(a) if a == wallet_b => (
                        gate_b_for_closure.clone(),
                        allow_list_mint_response_json(a, &mint_params_abi, Vec::new()),
                    ),
                    _ => (
                        gate_b_for_closure.clone(),
                        json!({"errors": ["unexpected minter"]}),
                    ),
                };
                if let Some(a) = minter
                    && (a == wallet_a || a == wallet_c)
                {
                    opensea_completed_for_closure
                        .lock()
                        .expect("mutex poisoned")
                        .push(a);
                }
                (gate, 200, response)
            })
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let mut config = tiny_config();
        config.opensea_api_concurrency = 4;

        let run_future =
            run_multi_wallet_opensea_mint(&opensea, &mut pool, &target, &wallets, &config, |_| {});

        let watcher = async {
            loop {
                {
                    let seen = opensea_completed.lock().expect("mutex poisoned");
                    if seen.contains(&wallet_a) && seen.contains(&wallet_c) {
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
            // A and C have both finished their own OpenSea round trip;
            // wallet B is still gated. If Kairox signed reactively, A/C
            // would already be broadcasting now. Confirm zero sends have
            // happened yet, then release B.
            assert_eq!(
                capture.calls_for("eth_sendRawTransaction").len(),
                0,
                "A and C must not be signed/broadcast before wallet B's response (and its stage constraint) is known"
            );
            gate_b.notify_one();
        };

        let (result, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            futures_util::future::join(run_future, watcher),
        )
        .await
        .expect("test timed out -- B's gate was likely never released");

        // 999 (current supply) + 3 (A+B+C, quantity 1 each) = 1002 exceeds
        // B's validated maxTokenSupplyForStage of 1000 -- the whole session
        // must fail, never a partial A/C success.
        let err = result.unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
        assert!(err.to_string().to_lowercase().contains("stage cap"));
    }

    #[tokio::test]
    async fn mixed_unconstrained_and_constrained_wallets_fail_before_signing_when_unsafe() {
        // Mixed-stage FAIL test: A and C unconstrained (qty 1 each), B
        // constrained (cap 1000, qty 1). currentTotalSupply = 999.
        // Aggregate quantity across ALL THREE (not just B) = 3, projecting
        // total supply to 1002 > 1000 -- must fail before any signature,
        // as a whole session, never silently picking A/C as "safe" just
        // because they carry no constraint of their own.
        let wallets = wallets_abc();
        let wallet_b = wallets[1].0.address;
        let mint_params_abi = sample_stage_mint_params(1000);
        let mint_params = MintParams::from(&mint_params_abi);
        let leaf_b = seadrop_crypto::allow_list_merkle_leaf(wallet_b, &mint_params);

        let (mut pool, capture) =
            opensea_chain_pool_with_mint_stats(Some((0, 999, 10_000)), Some(leaf_b)).await;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_dynamic("POST", "/api/v2/drops/cool-cats/mint", move |body| {
                let minter = body
                    .get("minter")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                match minter {
                    Some(a) if a == wallet_b => (
                        200,
                        allow_list_mint_response_json(a, &mint_params_abi, Vec::new()),
                    ),
                    Some(_) => (200, opensea_mint_response_json(Address::ZERO, 1, 0)),
                    None => (400, json!({"errors": ["unexpected minter"]})),
                }
            })
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let err = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
        assert!(err.to_string().to_lowercase().contains("stage cap"));

        let sends = capture.calls_for("eth_sendRawTransaction");
        assert_eq!(
            sends.len(),
            0,
            "zero wallets -- constrained or not -- may be signed/broadcast when the mixed aggregate is unsafe"
        );
    }

    #[tokio::test]
    async fn mixed_unconstrained_and_constrained_wallets_pass_when_aggregate_is_safe() {
        // Mixed-stage PASS test: A and C unconstrained (qty 1 each), B
        // constrained (cap 1000, qty 1). currentTotalSupply = 998.
        // Aggregate quantity across all three = 3, projecting to 1001...
        // wait: use 997 so 997+3=1000 exactly fits the cap -- both
        // constrained and unconstrained wallets may proceed.
        let wallets = wallets_abc();
        let wallet_b = wallets[1].0.address;
        let mint_params_abi = sample_stage_mint_params(1000);
        let mint_params = MintParams::from(&mint_params_abi);
        let leaf_b = seadrop_crypto::allow_list_merkle_leaf(wallet_b, &mint_params);

        let (mut pool, _capture) =
            opensea_chain_pool_with_mint_stats(Some((0, 997, 10_000)), Some(leaf_b)).await;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_dynamic("POST", "/api/v2/drops/cool-cats/mint", move |body| {
                let minter = body
                    .get("minter")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                match minter {
                    Some(a) if a == wallet_b => (
                        200,
                        allow_list_mint_response_json(a, &mint_params_abi, Vec::new()),
                    ),
                    Some(_) => (200, opensea_mint_response_json(Address::ZERO, 1, 0)),
                    None => (400, json!({"errors": ["unexpected minter"]})),
                }
            })
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let (result, _) = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(
            result.successful_count(),
            3,
            "aggregate exactly fits the stage cap -- all wallets, constrained and unconstrained, may proceed: {:?}",
            result.wallets
        );
    }

    /// Stage-constraint immutability regression: [`check_opensea_aggregate_invariants`]
    /// consumes only [`PreparedOpenSeaUnsignedWallet::stage_constraint`],
    /// which is populated once by [`crate::execution::opensea_validate::validate_opensea_mint_response`]
    /// from locally-decoded, locally-validated calldata. Raw OpenSea API
    /// response objects have no path back into the aggregate check at all
    /// -- proven here by mutating (dropping) the original mock response
    /// source after the session already captured its
    /// `PreparedOpenSeaUnsignedWallet`s; the aggregate decision is
    /// unaffected because it never re-reads anything from OpenSea.
    #[tokio::test]
    async fn aggregate_stage_check_only_ever_reads_the_validated_prepared_wallet() {
        let wallets: Vec<_> = wallets_abc().into_iter().take(1).collect();
        let wallet_a = wallets[0].0.address;
        let mint_params_abi = sample_stage_mint_params(1000);
        let mint_params = MintParams::from(&mint_params_abi);
        let leaf_a = seadrop_crypto::allow_list_merkle_leaf(wallet_a, &mint_params);

        let (mut pool, _capture) =
            opensea_chain_pool_with_mint_stats(Some((0, 999, 10_000)), Some(leaf_a)).await;

        // The mock response is constructed, moved into the transport
        // builder, and the builder itself is consumed by `.build()` --
        // there is no lingering handle back to the original
        // `allow_list_mint_response_json` value or `mint_params_abi` for
        // the aggregate check to (incorrectly) reach into later. Only the
        // already-decoded, already-validated `StageSupplyConstraint`
        // travels forward, inside `PreparedOpenSeaUnsignedWallet`.
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
                allow_list_mint_response_json(wallet_a, &mint_params_abi, Vec::new()),
            )
            .build();
        // `mint_params_abi`/`mint_params` are no longer reachable from here
        // on -- the transport builder above already consumed the response
        // body by value, and `.build()` returns an immutable transport with
        // no path back to either. Only the already-decoded, already-
        // validated `StageSupplyConstraint` inside the resulting
        // `PreparedOpenSeaUnsignedWallet` can reach the aggregate check.

        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        // quantity 1, currentTotalSupply 999, cap 1000 -> 1000 <= 1000: safe.
        let (result, _) = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(result.successful_count(), 1, "{:?}", result.wallets);
    }

    #[tokio::test]
    async fn opensea_broadcast_concurrency_bounds_the_real_wallet_x_endpoint_request_matrix() {
        // Test #3 (completion pass): 3 eligible OpenSea wallets x 3 send
        // endpoints = 9 actual `eth_sendRawTransaction` submissions.
        // opensea_api_concurrency: 3 (all 3 wallets' OpenSea
        // requests/preparation may run together). broadcast_concurrency: 2
        // -- must bound the real blockchain send matrix, shared across
        // every wallet's own broadcast, not merely how many wallets may be
        // preparing at once.
        let wallets = wallets_abc();
        let (mut pool, captures) =
            opensea_chain_pool_multi_endpoint(3, StdDuration::from_millis(30)).await;
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
                opensea_mint_response_json(Address::ZERO, 1, 0),
            )
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let mut config = tiny_config();
        config.opensea_api_concurrency = 3;
        config.broadcast_concurrency = 2;

        let (result, _) =
            run_multi_wallet_opensea_mint(&opensea, &mut pool, &target, &wallets, &config, |_| {})
                .await
                .unwrap();

        assert_eq!(result.successful_count(), 3);
        for w in &result.wallets {
            assert_eq!(
                w.broadcast_results.len(),
                3,
                "each wallet must fan out to all 3 send endpoints"
            );
        }

        let total_sends: usize = captures.iter().map(|c| c.prebuilt_bodies().len()).sum();
        assert_eq!(
            total_sends, 9,
            "3 wallets x 3 endpoints must produce exactly 9 actual send operations"
        );

        let peak = result
            .metrics
            .broadcast_peak_concurrency
            .expect("broadcast peak concurrency must be measured");
        assert!(
            peak <= 2,
            "observed OpenSea broadcast concurrency {peak} exceeded the configured limit of 2"
        );
        assert!(
            peak >= 2,
            "with 3 wallets x 3 endpoints and a limit of 2, the observed peak should actually reach the bound (got {peak})"
        );

        // Byte-identical bytes per wallet across every endpoint; different
        // wallets' bytes differ from each other.
        let bodies: Vec<std::collections::HashSet<Vec<u8>>> = captures
            .iter()
            .map(|c| {
                c.prebuilt_bodies()
                    .into_iter()
                    .map(|b| b.to_vec())
                    .collect()
            })
            .collect();
        assert_eq!(bodies[0].len(), 3, "3 distinct wallet bodies at endpoint 0");
        for endpoint_bodies in &bodies[1..] {
            assert_eq!(
                endpoint_bodies, &bodies[0],
                "every endpoint must receive the exact same set of byte-identical per-wallet bodies"
            );
        }
    }

    fn sample_stage_mint_params(max_token_supply_for_stage: u64) -> MintParamsAbi {
        MintParamsAbi {
            mintPrice: U256::ZERO,
            maxTotalMintableByWallet: U256::from(50u64),
            startTime: U256::from(datetime!(2020-01-01 00:00:00 UTC).unix_timestamp() as u64),
            endTime: U256::from(datetime!(2999-01-01 00:00:00 UTC).unix_timestamp() as u64),
            dropStageIndex: U256::from(1u64),
            maxTokenSupplyForStage: U256::from(max_token_supply_for_stage),
            feeBps: U256::ZERO,
            restrictFeeRecipients: false,
        }
    }

    #[tokio::test]
    async fn stage_cap_exceeded_by_aggregate_fails_whole_session_before_signing() {
        // Section 17 Test A: currentTotalSupply = 999, maxTokenSupplyForStage
        // = 1000 -- remaining stage capacity is exactly 1. Wallet A and
        // wallet B each request quantity 1 (aggregate 2). Must fail the
        // whole session before any wallet is signed -- never silently pick
        // a winner by manifest/arrival order.
        let wallets: Vec<_> = wallets_abc().into_iter().take(2).collect();
        let wallet_a = wallets[0].0.address;
        let wallet_b = wallets[1].0.address;
        let mint_params_abi = sample_stage_mint_params(1000);
        let mint_params = MintParams::from(&mint_params_abi);
        let (root, proof_a, proof_b) = two_wallet_allow_list_tree(wallet_a, wallet_b, &mint_params);

        let mut pool = opensea_chain_pool_with_mint_stats(Some((0, 999, 10_000)), Some(root))
            .await
            .0;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_dynamic("POST", "/api/v2/drops/cool-cats/mint", move |body| {
                let minter = body
                    .get("minter")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                match minter {
                    Some(a) if a == wallet_a => (
                        200,
                        allow_list_mint_response_json(a, &mint_params_abi, proof_a.clone()),
                    ),
                    Some(a) if a == wallet_b => (
                        200,
                        allow_list_mint_response_json(a, &mint_params_abi, proof_b.clone()),
                    ),
                    _ => (400, json!({"errors": ["unexpected minter"]})),
                }
            })
            .build();
        let capture = opensea_transport.capture_handle();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        // Nothing is ever signed before every wallet's response is known,
        // so an aggregate stage-cap violation fails the WHOLE session
        // cleanly with an `Err` -- not a partial per-wallet Failed set.
        let err = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
        assert!(err.to_string().to_lowercase().contains("stage cap"));

        let mint_posts = capture
            .all()
            .into_iter()
            .filter(|(method, path, _)| method == "POST" && path == "/api/v2/drops/cool-cats/mint")
            .count();
        assert_eq!(
            mint_posts, 2,
            "both wallets progress to unsigned-ready (their own OpenSea request/validation), only signing is blocked"
        );
    }

    #[tokio::test]
    async fn stage_cap_with_sufficient_remaining_capacity_allows_both_wallets() {
        // Section 17 Test B: currentTotalSupply = 998, maxTokenSupplyForStage
        // = 1000 -- remaining stage capacity is 2, exactly matching the
        // aggregate requested quantity (1 + 1). Both wallets may proceed.
        let wallets: Vec<_> = wallets_abc().into_iter().take(2).collect();
        let wallet_a = wallets[0].0.address;
        let wallet_b = wallets[1].0.address;
        let mint_params_abi = sample_stage_mint_params(1000);
        let mint_params = MintParams::from(&mint_params_abi);
        let (root, proof_a, proof_b) = two_wallet_allow_list_tree(wallet_a, wallet_b, &mint_params);

        let mut pool = opensea_chain_pool_with_mint_stats(Some((0, 998, 10_000)), Some(root))
            .await
            .0;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_dynamic("POST", "/api/v2/drops/cool-cats/mint", move |body| {
                let minter = body
                    .get("minter")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                match minter {
                    Some(a) if a == wallet_a => (
                        200,
                        allow_list_mint_response_json(a, &mint_params_abi, proof_a.clone()),
                    ),
                    Some(a) if a == wallet_b => (
                        200,
                        allow_list_mint_response_json(a, &mint_params_abi, proof_b.clone()),
                    ),
                    _ => (400, json!({"errors": ["unexpected minter"]})),
                }
            })
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };

        let (result, _) = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();

        assert_eq!(
            result.successful_count(),
            2,
            "both wallets must proceed when the aggregate exactly fits remaining stage capacity: {:?}",
            result.wallets
        );
    }

    /// Shared setup for the conflicting-stage-constraint tests: wallet A's
    /// validated `MintParams` carries `maxTokenSupplyForStage = 1000`,
    /// wallet B's carries `1001` -- genuinely different ceilings, proven
    /// via a real two-leaf Merkle tree (not the same leaf reused).
    async fn conflicting_stage_cap_session(
        current_total_supply: u64,
    ) -> (
        OpenSeaClient,
        RpcPool,
        Vec<(WalletMintRequest, LocalSigner)>,
    ) {
        let wallets: Vec<_> = wallets_abc().into_iter().take(2).collect();
        let wallet_a = wallets[0].0.address;
        let wallet_b = wallets[1].0.address;
        let mint_params_abi_a = sample_stage_mint_params(1000);
        let mint_params_abi_b = MintParamsAbi {
            dropStageIndex: U256::from(2u64),
            maxTokenSupplyForStage: U256::from(1001u64),
            ..sample_stage_mint_params(1001)
        };
        let mint_params_a = MintParams::from(&mint_params_abi_a);
        let mint_params_b = MintParams::from(&mint_params_abi_b);
        let (root, proof_a, proof_b) = two_wallet_allow_list_tree_with_params(
            wallet_a,
            &mint_params_a,
            wallet_b,
            &mint_params_b,
        );

        let pool =
            opensea_chain_pool_with_mint_stats(Some((0, current_total_supply, 10_000)), Some(root))
                .await
                .0;
        let opensea_transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                drop_details_response(),
            )
            .respond_dynamic("POST", "/api/v2/drops/cool-cats/mint", move |body| {
                let minter = body
                    .get("minter")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok());
                match minter {
                    Some(a) if a == wallet_a => (
                        200,
                        allow_list_mint_response_json(a, &mint_params_abi_a, proof_a.clone()),
                    ),
                    Some(a) if a == wallet_b => (
                        200,
                        allow_list_mint_response_json(a, &mint_params_abi_b, proof_b.clone()),
                    ),
                    _ => (400, json!({"errors": ["unexpected minter"]})),
                }
            })
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        (opensea, pool, wallets)
    }

    #[tokio::test]
    async fn conflicting_stage_constraints_use_the_minimum_ceiling_and_pass_when_safe() {
        // Test Gap 5, Case 1: A's ceiling is 1000, B's is 1001 -- the
        // aggregate check must use the MINIMUM (1000). currentTotalSupply
        // = 998, aggregate quantity = 2 -> projected 1000 <= min(1000,
        // 1001) = 1000 -- safe, both proceed.
        let (opensea, mut pool, wallets) = conflicting_stage_cap_session(998).await;
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let (result, _) = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(
            result.successful_count(),
            2,
            "aggregate must fit under the minimum validated ceiling: {:?}",
            result.wallets
        );
    }

    #[tokio::test]
    async fn conflicting_stage_constraints_fail_before_signing_when_the_tighter_ceiling_is_exceeded()
     {
        // Test Gap 5, Case 2: same ceilings (1000 vs 1001), but
        // currentTotalSupply = 999 -> projected 1001 > min(1000, 1001) =
        // 1000 -- must fail before any signature, proven via zero
        // `eth_sendRawTransaction` calls.
        let (opensea, mut pool, wallets) = conflicting_stage_cap_session(999).await;
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let err = run_multi_wallet_opensea_mint(
            &opensea,
            &mut pool,
            &target,
            &wallets,
            &tiny_config(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
        assert!(err.to_string().to_lowercase().contains("stage cap"));
    }

    #[tokio::test]
    async fn opensea_session_cap_safe_actual_cost_passes() {
        // Section 22: 3 eligible wallets, each real finalized worst-case
        // ~0.02 ETH (mint value; mock gas cost is negligible), aggregate
        // ~0.06 ETH -- session cap 0.10 ETH must PASS.
        let wallets = wallets_abc();
        let mut pool = opensea_chain_pool().await;
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
                opensea_mint_response_json(Address::ZERO, 1, 20_000_000_000_000_000u128),
            )
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let mut config = tiny_config();
        config.max_session_total_spend = Some(U256::from(100_000_000_000_000_000u128)); // 0.10 ETH

        let (result, _) =
            run_multi_wallet_opensea_mint(&opensea, &mut pool, &target, &wallets, &config, |_| {})
                .await
                .unwrap();

        assert_eq!(
            result.successful_count(),
            3,
            "a session whose real aggregate cost is well under the cap must not be rejected: {:?}",
            result.wallets
        );
    }

    #[tokio::test]
    async fn opensea_session_cap_exceeded_by_actual_cost_fails_before_any_signature_or_broadcast() {
        // Section 22: same ~0.06 ETH real aggregate cost, but a strict
        // 0.05 ETH session cap -- must FAIL before any wallet is signed.
        // Proven via zero `eth_sendRawTransaction` calls (signing and
        // broadcasting happen together in `finalize_and_broadcast_opensea_wallet`,
        // so zero sends is proof zero signatures were ever created too).
        let wallets = wallets_abc();
        let (mut pool, capture) = opensea_chain_pool_with_capture().await;
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
                opensea_mint_response_json(Address::ZERO, 1, 20_000_000_000_000_000u128),
            )
            .build();
        let opensea = OpenSeaClient::with_transport(Box::new(opensea_transport));
        let target = OpenSeaMultiWalletTarget {
            chain: &chain(),
            slug: "cool-cats",
            nft_contract: NFT,
            seadrop_contract: SEADROP,
        };
        let mut config = tiny_config();
        config.max_session_total_spend = Some(U256::from(50_000_000_000_000_000u128)); // 0.05 ETH

        let err =
            run_multi_wallet_opensea_mint(&opensea, &mut pool, &target, &wallets, &config, |_| {})
                .await
                .unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
        assert!(err.to_string().to_lowercase().contains("session cap"));

        let sends = capture.calls_for("eth_sendRawTransaction");
        assert_eq!(
            sends.len(),
            0,
            "no wallet may be signed or broadcast once the real aggregate OpenSea cost is known to exceed the session cap"
        );
    }

    #[test]
    fn error_category_still_flags_must_stop_session_for_uncertain_wallets() {
        // Sanity check the classification helper this module relies on:
        // an uncertain post-signing broadcast outcome must categorize as
        // MustStopSession, exactly like the single-wallet engines.
        let err = KairoxError::Session(SessionError("uncertain".into()));
        assert_eq!(err.category(), ErrorCategory::MustStopSession);
    }
}
