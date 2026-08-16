//! `kairox bench` — connects (pre-warms) every configured endpoint for a
//! chain and reports latency/role/capability. Never signs or broadcasts
//! anything.

use crate::chain::config::{ProcessEnv, load_chain_endpoints};
use crate::chain::endpoint::RpcEndpoint;
use crate::chain::pool::{ConnectOutcome, RpcPool};
use crate::chain::registry::ChainRegistry;
use crate::cli::args::BenchArgs;
use crate::cli::context::resolve_chain;
use crate::execution::errors::KairoxError;

pub async fn run(args: BenchArgs) -> Result<(), KairoxError> {
    let registry = ChainRegistry::builtin();
    let resolved = resolve_chain(&registry, &args.chain_args)?;

    let endpoints: Vec<RpcEndpoint> = if let Some(url) = &args.chain_args.rpc_url {
        vec![RpcEndpoint::new(
            url.clone(),
            crate::chain::endpoint::EndpointRole::ReadWrite,
        )]
    } else {
        load_chain_endpoints(&ProcessEnv, resolved.info.chain_id)?.endpoints
    };

    println!(
        "Benchmarking {} endpoint(s) on {} (chain id {})",
        endpoints.len(),
        resolved.info.name,
        resolved.info.chain_id
    );
    if endpoints.is_empty() {
        println!(
            "No endpoints configured. Set KAIROX_RPC_{}_0_URL or pass --rpc-url.",
            resolved.info.chain_id
        );
        return Ok(());
    }

    let (pool, reports) = RpcPool::connect_all(resolved.info.chain_id, &endpoints).await;

    for report in &reports {
        let label = report
            .label
            .clone()
            .unwrap_or_else(|| "(unlabeled)".to_string());
        match &report.outcome {
            ConnectOutcome::Connected { latency_ms } => {
                println!(
                    "  {label} role={:?} -> connected in {latency_ms} ms",
                    report.role
                );
            }
            ConnectOutcome::Failed { latency_ms, error } => {
                println!(
                    "  {label} role={:?} -> FAILED after {latency_ms} ms: {error}",
                    report.role
                );
            }
        }
    }

    println!();
    println!(
        "{} of {} endpoints connected; {} read-capable, {} send-capable",
        pool.len(),
        endpoints.len(),
        pool.read_capable().len(),
        pool.send_capable().len()
    );

    Ok(())
}
