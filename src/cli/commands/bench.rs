//! `kairox bench` — connects (pre-warms), benchmarks, and reports the
//! selection status of every configured endpoint for a chain. Never signs
//! or broadcasts anything.

use crate::chain::config::{ProcessEnv, load_chain_endpoints};
use crate::chain::endpoint::RpcEndpoint;
use crate::chain::pool::RpcPool;
use crate::chain::registry::ChainRegistry;
use crate::cli::args::BenchArgs;
use crate::cli::context::resolve_chain_info_and_runtime;
use crate::cli::format::{format_benchmark_report, mask_url};
use crate::execution::errors::KairoxError;
use crate::execution::profile::ExecutionProfile;

pub async fn run(
    args: BenchArgs,
    config_path: Option<&std::path::Path>,
) -> Result<(), KairoxError> {
    let registry = ChainRegistry::builtin();
    let (resolved, runtime) =
        resolve_chain_info_and_runtime(&registry, &args.chain_args, config_path)?;

    let endpoints: Vec<RpcEndpoint> = if let Some(url) = &args.chain_args.rpc_url {
        vec![RpcEndpoint::new(
            url.clone(),
            crate::chain::endpoint::EndpointRole::ReadWrite,
        )]
    } else {
        let from_config =
            crate::cli::context::config_endpoints_for_chain(&resolved, runtime.config.as_ref());
        if !from_config.is_empty() {
            from_config
        } else {
            load_chain_endpoints(&ProcessEnv, resolved.chain_id)?.endpoints
        }
    };

    println!(
        "Benchmarking {} endpoint(s) on {} (chain id {})",
        endpoints.len(),
        resolved.name,
        resolved.chain_id
    );
    if endpoints.is_empty() {
        println!(
            "No endpoints configured. Set KAIROX_RPC_{}_0_URL or pass --rpc-url.",
            resolved.chain_id
        );
        return Ok(());
    }

    // BENCHMARK/WARM: connecting is the pre-warm step; benchmark_all takes
    // the bounded, repeated read-latency samples on top of it.
    let (mut pool, reports) = RpcPool::connect_all(resolved.chain_id, &endpoints).await;

    let profile = ExecutionProfile::for_chain(resolved.chain_id);
    let mut benchmark_config = profile.benchmark_policy;
    if let Some(samples) = args.samples {
        benchmark_config.sample_count = samples;
    }
    if let Some(delay_ms) = args.sample_delay_ms {
        benchmark_config.sample_delay = std::time::Duration::from_millis(delay_ms);
    }
    pool.benchmark_all(&benchmark_config).await;

    // SELECT: same deterministic selection the live pipeline would use.
    // Matched back to a benchmark record by pointer identity, not by label
    // — operator-supplied labels may be absent or repeated across
    // endpoints, so they are never a safe join key.
    let selected_read_ptr = pool.preferred_read().map(std::ptr::from_ref);
    let selected_send_ptrs: Vec<*const crate::chain::rpc::RpcClient> = pool
        .select_send_endpoints(&profile.health_policy)
        .into_iter()
        .map(std::ptr::from_ref)
        .collect();
    let selected_read_label = pool.preferred_read().and_then(|c| c.label());

    // `reports` is 1:1 with `endpoints` (both connected and failed); the
    // pool only holds an entry (client + benchmark) per *successfully*
    // connected client, so track that subset separately as we walk
    // `reports`.
    let mut connected = pool.clients_with_benchmarks();
    for (endpoint, report) in endpoints.iter().zip(reports.iter()) {
        let masked_url = mask_url(&endpoint.url);
        match &report.outcome {
            crate::chain::pool::ConnectOutcome::Failed { latency_ms, error } => {
                println!(
                    "{} {masked_url}\n    role={:?} status=UNREACHABLE latency={latency_ms}ms error={error}",
                    report
                        .label
                        .clone()
                        .unwrap_or_else(|| "(unlabeled)".to_string()),
                    report.role
                );
            }
            crate::chain::pool::ConnectOutcome::WrongChain {
                latency_ms,
                expected,
                reported,
            } => {
                println!(
                    "{} {masked_url}\n    role={:?} status=WRONG_CHAIN expected={expected} reported={reported} latency={latency_ms}ms",
                    report
                        .label
                        .clone()
                        .unwrap_or_else(|| "(unlabeled)".to_string()),
                    report.role
                );
            }
            crate::chain::pool::ConnectOutcome::Connected { .. } => {
                let (client, bench) = connected
                    .next()
                    .expect("one benchmark entry per successfully connected endpoint");
                let client_ptr = std::ptr::from_ref(client);
                let selected_read = selected_read_ptr == Some(client_ptr);
                let selected_send = selected_send_ptrs.contains(&client_ptr);
                let block = format_benchmark_report(
                    &masked_url,
                    resolved.chain_id,
                    bench,
                    selected_read,
                    selected_send,
                );
                println!("{block}");
            }
        }
        println!();
    }

    println!(
        "{} of {} endpoints connected; {} read-capable, {} send-capable; selected read: {}",
        pool.len(),
        endpoints.len(),
        pool.read_capable().len(),
        pool.send_capable().len(),
        selected_read_label.unwrap_or("(unlabeled)"),
    );

    report_opensea_locality(resolved.chain_id).await;

    Ok(())
}

/// Diagnostic-only network-locality report for the official OpenSea REST
/// origin: real, read-only `GET /api/v2/chain/{chain}/contract/{address}`
/// requests against the zero address, timed individually. Purely
/// observational: never asserted against a threshold, never used to
/// change any endpoint/infrastructure choice automatically -- an
/// operator decides what (if anything) to do with this. Skipped
/// entirely (with a clear reason) when no OpenSea API key is configured
/// or the chain has no known OpenSea mapping -- never a hard failure of
/// `bench` itself.
///
/// Round 6 item 7: deliberately never calls the first sample "cold" --
/// this uses the same already-warm, already-reused `OpenSeaClient`
/// `load_opensea_client` returns (the same client `watch`/`mint` use),
/// so a prior request on this exact process may already have
/// established the underlying connection. "first measured request" /
/// "subsequent request" describe exactly what is actually known, never
/// a claim about TCP/TLS connection state this code cannot observe.
/// Each response is classified by the real HTTP-status-derived
/// [`crate::opensea::errors::OpenSeaError`] variant `get_contract`
/// already returns (200/404/401/403/429/5xx/timeout/transport failure
/// are all independently distinguishable outcomes here; response bodies
/// are never printed, so no secret-bearing content can leak through
/// this diagnostic).
async fn report_opensea_locality(chain_id: crate::chain::registry::ChainId) {
    println!();
    let Some(chain_identifier) = crate::opensea::models::opensea_chain_identifier(chain_id) else {
        println!("OpenSea REST origin: chain id {chain_id} has no known OpenSea mapping; skipped.");
        return;
    };
    let opensea = match super::mint::load_opensea_client(std::time::Duration::from_secs(10)) {
        Ok(client) => client,
        Err(_) => {
            println!(
                "OpenSea REST origin ({chain_identifier}): KAIROX_OPENSEA_API_KEY not configured; \
                 skipped."
            );
            return;
        }
    };

    println!("OpenSea REST origin ({chain_identifier}) -- diagnostic only, never authoritative:");
    const SAMPLES: usize = 3;
    let mut latencies_ms = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let started = std::time::Instant::now();
        let outcome = opensea
            .get_contract(chain_identifier, alloy_primitives::Address::ZERO)
            .await;
        let elapsed_ms = started.elapsed().as_millis();
        let phase = if i == 0 {
            "first measured request"
        } else {
            "subsequent request"
        };
        let status = match &outcome {
            Ok(Some(_)) => "HTTP 200 (unexpectedly found a contract record)".to_string(),
            Ok(None) => "HTTP 404 (no record for the zero address, as expected)".to_string(),
            Err(crate::opensea::errors::OpenSeaError::AuthenticationFailed) => {
                "HTTP 401/403 (authentication failed)".to_string()
            }
            Err(crate::opensea::errors::OpenSeaError::RateLimited) => {
                "HTTP 429 (rate limited)".to_string()
            }
            Err(crate::opensea::errors::OpenSeaError::ServerError { .. }) => {
                "HTTP 5xx (server error)".to_string()
            }
            Err(crate::opensea::errors::OpenSeaError::ApiTimeout) => {
                "timeout (no HTTP response received)".to_string()
            }
            Err(crate::opensea::errors::OpenSeaError::ApiUnavailable { .. }) => {
                "transport failure (no HTTP response received)".to_string()
            }
            Err(crate::opensea::errors::OpenSeaError::MalformedApiResponse { detail }) => {
                format!("unexpected response ({detail})")
            }
            Err(other) => format!("unexpected error ({other})"),
        };
        println!("  request {} ({phase}): {elapsed_ms}ms -- {status}", i + 1);
        latencies_ms.push(elapsed_ms);
    }
    if latencies_ms.len() > 1 {
        let first = latencies_ms[0];
        let subsequent_mean =
            latencies_ms[1..].iter().sum::<u128>() / (latencies_ms.len() - 1) as u128;
        println!(
            "  first measured request: {first}ms; mean of {} subsequent request(s): \
             {subsequent_mean}ms",
            latencies_ms.len() - 1
        );
    }
}
