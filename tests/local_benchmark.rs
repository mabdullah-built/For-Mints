//! A deterministic LOCAL benchmark of Kairox's broadcast-dispatch
//! machinery, against an in-process mock transport with an artificial
//! fixed per-call delay -- NOT a measurement of real internet/RPC
//! latency. It exists to make dispatch-scheduler overhead, dispatch skew,
//! and peak concurrency observable and regression-testable without any
//! network access.
//!
//! Run explicitly (skipped by a plain `cargo test` run):
//!
//! ```text
//! cargo test --test local_benchmark -- --ignored --nocapture
//! ```

use std::time::Duration;

use alloy_primitives::{B256, Bytes};
use kairox::chain::endpoint::EndpointRole;
use kairox::chain::mock::MockTransport;
use kairox::chain::rpc::{PreparedBroadcast, RpcClient};
use kairox::execution::broadcast::{BroadcastJob, broadcast_to_all, dispatch_broadcast_matrix};

const SIMULATED_ENDPOINT_LATENCY: Duration = Duration::from_millis(5);

async fn mock_send_client(label: &str) -> RpcClient {
    let transport = MockTransport::builder()
        .respond("eth_chainId", serde_json::json!("0x1"))
        .respond("eth_blockNumber", serde_json::json!("0x1"))
        // `echo_raw_transaction_hash`'s `respond_dynamic` bypasses the
        // plain `.delay()` entry path entirely (dynamic handlers are
        // checked first in `MockTransport::call`), so the delay has to be
        // attached directly to the dynamic computation instead.
        .respond_dynamic_result_delayed("eth_sendRawTransaction", |params| {
            let raw_hex = params
                .get(0)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("0x")
                .trim_start_matches("0x");
            let bytes = hex::decode(raw_hex).unwrap_or_default();
            let hash = alloy_primitives::keccak256(&bytes);
            (
                SIMULATED_ENDPOINT_LATENCY,
                Ok(serde_json::json!(format!("0x{}", hex::encode(hash)))),
            )
        })
        .build();
    RpcClient::connect(
        Box::new(transport),
        1,
        EndpointRole::ReadWrite,
        Some(label.to_string()),
    )
    .await
    .expect("mock endpoint connects")
}

fn dummy_prepared() -> PreparedBroadcast {
    let raw = Bytes::from_static(&[0x02, 0x00]);
    // `echo_raw_transaction_hash` on the mock transport returns the real
    // keccak256 of whatever raw bytes it receives, so match that here to
    // get a clean `Accepted` outcome rather than a hash-mismatch
    // rejection -- either classification would still exercise the same
    // dispatch timing, but `Accepted` is the honest common case to show.
    let tx_hash: B256 = alloy_primitives::keccak256(&raw);
    PreparedBroadcast::build(tx_hash, raw)
}

#[tokio::test]
#[ignore = "local benchmark, not a correctness test -- run explicitly with --ignored --nocapture"]
async fn one_wallet_three_endpoints_dispatch_skew() {
    let a = mock_send_client("endpoint-a").await;
    let b = mock_send_client("endpoint-b").await;
    let c = mock_send_client("endpoint-c").await;
    let clients = [&a, &b, &c];
    let prepared = dummy_prepared();

    let started = std::time::Instant::now();
    let results = broadcast_to_all(&clients, &prepared).await;
    let wall = started.elapsed();

    println!("=== LOCAL FRAMEWORK BENCHMARK (not real network latency) ===");
    println!("scenario: 1 wallet x 3 mock endpoints, unbounded fan-out");
    println!("simulated per-endpoint latency: {SIMULATED_ENDPOINT_LATENCY:?}");
    println!("total wall time: {wall:?}");
    for r in &results {
        println!(
            "  endpoint={} latency_ms={:?} outcome={:?}",
            r.label, r.latency_ms, r.outcome
        );
    }
    assert_eq!(results.len(), 3);
    // Unbounded fan-out over a fixed simulated per-call delay should
    // complete close to one delay's worth of wall time, not three --
    // proves the three sends genuinely ran concurrently, not serially.
    assert!(
        wall < SIMULATED_ENDPOINT_LATENCY * 3,
        "expected concurrent dispatch to beat 3x serial time, took {wall:?}"
    );
}

#[tokio::test]
#[ignore = "local benchmark, not a correctness test -- run explicitly with --ignored --nocapture"]
async fn three_wallets_three_endpoints_bounded_matrix() {
    let clients: Vec<RpcClient> = vec![
        mock_send_client("endpoint-a").await,
        mock_send_client("endpoint-b").await,
        mock_send_client("endpoint-c").await,
    ];
    let prepared = dummy_prepared();

    // 3 wallets x 3 endpoints = 9 jobs, endpoint-major (matches the real
    // multi-wallet caller's fairness ordering), bounded to 3 concurrent
    // in-flight sends across the whole matrix.
    let mut jobs = Vec::new();
    for wallet_index in 0..3 {
        for client in &clients {
            jobs.push(BroadcastJob {
                wallet_index,
                client,
                prepared: &prepared,
            });
        }
    }

    let started = std::time::Instant::now();
    let (results, metrics) = dispatch_broadcast_matrix(jobs, 3).await;
    let wall = started.elapsed();

    println!("=== LOCAL FRAMEWORK BENCHMARK (not real network latency) ===");
    println!("scenario: 3 wallets x 3 mock endpoints, concurrency bound 3");
    println!("simulated per-endpoint latency: {SIMULATED_ENDPOINT_LATENCY:?}");
    println!("total wall time: {wall:?}");
    println!("peak_concurrency: {}", metrics.peak_concurrency);
    let skew = match (metrics.first_dispatch_at, metrics.last_dispatch_at) {
        (Some(first), Some(last)) => Some(last - first),
        _ => None,
    };
    println!("dispatch skew (last - first dispatch): {skew:?}");

    assert_eq!(results.len(), 9);
    assert!(metrics.peak_concurrency <= 3);
    // 9 jobs bounded to 3 concurrent should take roughly 3 "rounds" of
    // the simulated delay, not 9 -- proves the bound is real (not merely
    // configured) without needing real network timing to observe it.
    assert!(
        wall < SIMULATED_ENDPOINT_LATENCY * 9,
        "expected the concurrency bound to beat fully-serial time, took {wall:?}"
    );
}
