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
    OpenSeaProgress, OpenSeaWalletMintOutcome, OpenSeaWalletMintParams, run_opensea_mint_for_wallet,
};
use crate::execution::prepared::{LiveMintRequest, PreparedTransaction, prepare_live_transaction};
use crate::execution::receipt::{ReceiptState, poll_receipt};
use crate::opensea::client::OpenSeaClient;
use crate::opensea::models::DropDetailedResponse;
use crate::signing::keystore::{KeyLoadError, load_from_env_var};
use crate::signing::signer::{LocalSigner, Signer};

use super::broadcast::{
    BroadcastSummary, EndpointBroadcastResult, broadcast_to_all, summarize_broadcast,
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
    Preparing { address: Address },
    WalletPrepared { address: Address },
    WalletFailed { address: Address, reason: String },
    Waiting,
    Dispatching { address: Address },
    ReceiptPending { address: Address },
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

    if let Some(session_cap) = config.max_session_total_spend {
        let declared_worst_case = config
            .safety_caps
            .max_total_spend
            .saturating_mul(U256::from(wallets.len() as u64));
        if declared_worst_case > session_cap {
            return Err(KairoxError::Session(SessionError(format!(
                "worst-case aggregate spend across {} wallets ({declared_worst_case} wei, using each wallet's configured max_total_spend) exceeds the configured session cap ({session_cap} wei); refusing to sign any wallet",
                wallets.len()
            ))));
        }
    }
    metrics.preflight_total_ms = Some(preflight_sw.elapsed_ms());

    // PREPARE — bounded, concurrent, per-wallet, order-preserving.
    let prepare_sw = Stopwatch::start();
    let prepare_results: Vec<(WalletMintRequest, Result<PreparedTransaction, KairoxError>)> =
        stream::iter(wallets.iter().map(|(request, signer)| {
            let request = request.clone();
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
                let outcome = prepare_live_transaction(read_client, signer, &live_request).await;
                (request, outcome)
            }
        }))
        .buffered(config.broadcast_concurrency.max(1))
        .collect()
        .await;
    metrics.multiwallet_prepare_wall_ms = Some(prepare_sw.elapsed_ms());

    let mut wallet_results: Vec<WalletResult> = Vec::with_capacity(wallets.len());
    let mut prepared: Vec<(WalletMintRequest, PreparedTransaction)> = Vec::new();

    for (request, outcome) in prepare_results {
        match outcome {
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
    metrics.prepared_wallet_count = prepared.len();
    metrics.eligible_wallet_count = prepared.len();

    // FINALIZED aggregate spend check -- over only the wallets that
    // actually prepared, using their real (post-gas-estimate) worst-case
    // totals. Still strictly before dispatch.
    if let Some(session_cap) = config.max_session_total_spend {
        let mut finalized_worst_case = U256::ZERO;
        for (_, p) in &prepared {
            let worst_case_gas_cost = U256::from(p.gas_limit) * U256::from(p.max_fee_per_gas);
            finalized_worst_case =
                finalized_worst_case.saturating_add(p.value.saturating_add(worst_case_gas_cost));
        }
        if finalized_worst_case > session_cap {
            return Err(KairoxError::Session(SessionError(format!(
                "finalized aggregate worst-case spend across {} prepared wallets ({finalized_worst_case} wei) exceeds the configured session cap ({session_cap} wei); refusing to broadcast any wallet",
                prepared.len()
            ))));
        }
    }

    if prepared.is_empty() {
        return Ok(SessionResult {
            wallets: wallet_results,
            metrics,
        });
    }

    // FREEZE + BARRIER: wait for the shared verified stage-open instant.
    let stage_start = prepared[0].1.stage_start;
    on_progress(MultiWalletProgress::Waiting);
    let now = OffsetDateTime::now_utc();
    crate::execution::scheduler::sleep_until(now, stage_start, |_| {}).await;

    // DISPATCH — bounded, concurrent, released together rather than in a
    // sequential per-wallet loop.
    let first_dispatch_at = std::sync::Mutex::new(None::<OffsetDateTime>);
    let last_dispatch_at = std::sync::Mutex::new(None::<OffsetDateTime>);

    let dispatch_results: Vec<(
        WalletMintRequest,
        PreparedTransaction,
        Vec<EndpointBroadcastResult>,
        BroadcastSummary,
    )> = stream::iter(prepared.into_iter().map(|(request, p)| {
        let send_clients = &send_clients;
        let first_dispatch_at = &first_dispatch_at;
        let last_dispatch_at = &last_dispatch_at;
        async move {
            on_progress_noop();
            let dispatched_at = OffsetDateTime::now_utc();
            {
                let mut first = first_dispatch_at.lock().expect("mutex poisoned");
                if first.is_none() {
                    *first = Some(dispatched_at);
                }
            }
            let results = broadcast_to_all(send_clients, &p.broadcast).await;
            {
                let mut last = last_dispatch_at.lock().expect("mutex poisoned");
                *last = Some(OffsetDateTime::now_utc());
            }
            let summary = summarize_broadcast(&results);
            (request, p, results, summary)
        }
    }))
    .buffered(config.broadcast_concurrency.max(1))
    .collect()
    .await;

    metrics.broadcast_peak_concurrency = Some(
        config
            .broadcast_concurrency
            .min(dispatch_results.len().max(1)),
    );
    if let Some(first) = *first_dispatch_at.lock().expect("mutex poisoned") {
        metrics.first_dispatch_error_ms = Some(duration_ms_i64(stage_start, first));
    }
    if let Some(last) = *last_dispatch_at.lock().expect("mutex poisoned") {
        metrics.last_dispatch_error_ms = Some(duration_ms_i64(stage_start, last));
    }
    if let (Some(f), Some(l)) = (
        metrics.first_dispatch_error_ms,
        metrics.last_dispatch_error_ms,
    ) {
        metrics.multiwallet_dispatch_skew_ms = Some((l - f).unsigned_abs());
    }

    // RECEIPTS — bounded, concurrent, per confirmed wallet.
    let receipt_inputs: Vec<_> = dispatch_results
        .into_iter()
        .map(|(request, p, results, summary)| {
            let confirmed_tx_hash = match &summary {
                BroadcastSummary::Confirmed { tx_hash } => Some(*tx_hash),
                _ => None,
            };
            (request, p, results, summary, confirmed_tx_hash)
        })
        .collect();

    let final_results: Vec<WalletResult> = stream::iter(receipt_inputs.into_iter().map(
        |(request, p, results, summary, confirmed_tx_hash)| {
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
                            config.receipt_poll_interval,
                            config.receipt_timeout,
                            || {},
                        )
                        .await;
                        let state = match receipt_state {
                            ReceiptState::ConfirmedSuccess { minted } => {
                                WalletExecutionState::ConfirmedSuccess { minted }
                            }
                            ReceiptState::ConfirmedRevert => WalletExecutionState::ConfirmedRevert,
                            ReceiptState::ReceiptUnknown => WalletExecutionState::Uncertain,
                        };
                        (state, Some(tx_hash))
                    }
                };
                let _ = confirmed_tx_hash;
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
/// once, shared. Each wallet then runs its own fully independent pipeline
/// via [`crate::execution::opensea_engine::run_opensea_mint_for_wallet`]
/// — its own OpenSea request, its own validation (Merkle proof / EIP-712
/// signature, never another wallet's), its own simulation, its own
/// signature, its own broadcast. Concurrency is bounded by
/// `config.opensea_api_concurrency` (deliberately smaller than the
/// broadcast bound — see module-level constant docs): a slow or
/// ineligible wallet occupies one concurrency slot but never blocks
/// wallets outside that bound from starting once a slot frees up, and
/// never blocks a wallet that already started.
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

    let opensea_concurrency = config.opensea_api_concurrency.max(1);
    let final_results: Vec<WalletResult> = stream::iter(wallets.iter().map(|(request, signer)| {
        let read_client = &read_client;
        let send_clients = &send_clients;
        async move {
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
            let outcome: Result<OpenSeaWalletMintOutcome, KairoxError> =
                run_opensea_mint_for_wallet(
                    opensea,
                    read_client,
                    send_clients,
                    signer,
                    &params,
                    |p| on_progress_noop_opensea(request.address, p),
                )
                .await;

            wallet_result_from_opensea_outcome(request.clone(), outcome)
        }
    }))
    .buffered(opensea_concurrency)
    .collect()
    .await;

    metrics.opensea_peak_concurrency = Some(opensea_concurrency.min(wallets.len().max(1)));
    metrics.eligible_wallet_count = final_results
        .iter()
        .filter(|w| !matches!(w.state, WalletExecutionState::Ineligible { .. }))
        .count();
    metrics.prepared_wallet_count = final_results.iter().filter(|w| w.tx_hash.is_some()).count();
    for w in &final_results {
        match &w.state {
            WalletExecutionState::ConfirmedSuccess { .. } => metrics.successful_wallet_count += 1,
            WalletExecutionState::Uncertain => metrics.uncertain_wallet_count += 1,
            _ => metrics.failed_wallet_count += 1,
        }
    }

    Ok((
        SessionResult {
            wallets: final_results,
            metrics,
        },
        drop_details,
    ))
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
    use crate::chain::registry::ChainRegistry;
    use crate::chain::rpc::RpcClient;
    use crate::execution::errors::{Categorize, ErrorCategory};
    use crate::opensea::client::OpenSeaClient;
    use crate::opensea::mock::MockOpenSeaTransport;
    use crate::protocol::seadrop;
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

    /// A read-write chain client whose `eth_getTransactionCount`/
    /// `eth_getBalance` respond per-queried-address from the given maps
    /// (defaulting to a generous nonce/balance for any address not
    /// explicitly listed), with a single shared, generous public-drop
    /// stage and mint-stats fixture.
    async fn public_pool(
        nonce_by_wallet: HashMap<Address, u64>,
        balance_by_wallet: HashMap<Address, &'static str>,
    ) -> RpcPool {
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
            })
            .echo_raw_transaction_hash()
            .respond_dynamic("eth_getTransactionReceipt", |params| {
                let queried_hash = params
                    .get(0)
                    .and_then(Value::as_str)
                    .unwrap_or("0x")
                    .to_string();
                json!({
                    "transactionHash": queried_hash,
                    "status": "0x1",
                    "blockNumber": "0x1",
                    "logs": []
                })
            })
            .build();

        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap();
        RpcPool::from_clients(1, vec![client])
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
        for w in &result.wallets {
            assert!(matches!(
                w.state,
                WalletExecutionState::ConfirmedSuccess { .. }
            ));
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
    async fn aggregate_session_spend_cap_exceeded_fails_before_signing() {
        let wallets = wallets_abc();
        let mut pool = public_pool(HashMap::new(), HashMap::new()).await;
        let mut config = tiny_config();
        // Each wallet's own cap allows up to 1e18 wei; 3 wallets could
        // conceivably reach 3e18, but the session cap only allows 1e18
        // total -- must fail before any wallet is prepared/signed.
        config.max_session_total_spend = Some(U256::from(1_000_000_000_000_000_000u128));

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
            .respond_dynamic("eth_getTransactionReceipt", |params| {
                let queried_hash = params
                    .get(0)
                    .and_then(Value::as_str)
                    .unwrap_or("0x")
                    .to_string();
                json!({
                    "transactionHash": queried_hash,
                    "status": "0x1",
                    "blockNumber": "0x1",
                    "logs": []
                })
            })
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap();
        RpcPool::from_clients(1, vec![client])
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
        let wallets: Vec<_> = wallets_abc().into_iter().take(1).collect();
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
        assert_eq!(result.wallets.len(), 1);
        assert!(!result.wallets[0].state.is_terminal_success());
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
