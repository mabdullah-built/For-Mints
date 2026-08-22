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
/// requests (the zero address -- expected to 404, which is a perfectly
/// real round trip for latency purposes) against the address zero, timed
/// individually so an operator can see the cold-connection cost
/// separately from subsequent (TCP/TLS-reused) requests. Purely
/// observational: never asserted against a threshold, never used to
/// change any endpoint/infrastructure choice automatically -- an
/// operator decides what (if anything) to do with this. Skipped
/// entirely (with a clear reason) when no OpenSea API key is configured
/// or the chain has no known OpenSea mapping -- never a hard failure of
/// `bench` itself.
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
        let phase = if i == 0 { "cold" } else { "warm" };
        let status = match outcome {
            Ok(_) => "ok",
            Err(_) => "no-record-or-error (still a real round trip)",
        };
        println!("  request {} ({phase}): {elapsed_ms}ms ({status})", i + 1);
        latencies_ms.push(elapsed_ms);
    }
    if latencies_ms.len() > 1 {
        let cold = latencies_ms[0];
        let warm_mean = latencies_ms[1..].iter().sum::<u128>() / (latencies_ms.len() - 1) as u128;
        println!(
            "  cold request: {cold}ms; mean of {} subsequent (connection-reused) request(s): \
             {warm_mean}ms",
            latencies_ms.len() - 1
        );
    }
}
