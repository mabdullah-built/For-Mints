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

use alloy_primitives::{Address, B256, Bytes, U256, address};
use kairox::chain::endpoint::EndpointRole;
use kairox::chain::mock::MockTransport;
use kairox::chain::rpc::{PreparedBroadcast, RpcClient};
use kairox::execution::broadcast::{BroadcastJob, broadcast_to_all, dispatch_broadcast_matrix};
use kairox::signing::signer::{LocalSigner, Signer};
use kairox::signing::transaction::UnsignedEip1559Tx;

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

// =======================================================================
// PUBLIC engine: sign + serialize timing (mainnet competitive-mint
// hardening pass). No network involved -- this isolates exactly the
// Kairox-controlled work `finalize_signed_transaction` performs (real
// ECDSA signing over a real EIP-1559 signing hash, then RLP + hex +
// JSON-RPC-body serialization), the two steps that must be fully
// complete before the T=0 barrier for the "release already-signed,
// already-serialized bytes" invariant to hold. State-gathering (nonce,
// fee, balance, gas estimate) is excluded here since it's inherently
// RPC-latency-bound, not Kairox-controlled, and already measured
// end-to-end by `LatencyMetrics` on every real run.
// =======================================================================

const SEADROP: Address = address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5");

fn signer_for(seed: &str) -> LocalSigner {
    LocalSigner::from_bytes(alloy_primitives::keccak256(seed.as_bytes()).0).unwrap()
}

fn unsigned_tx_for(nonce: u64) -> UnsignedEip1559Tx {
    UnsignedEip1559Tx {
        chain_id: 4663,
        nonce,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        gas_limit: 180_000,
        to: SEADROP,
        value: U256::ZERO,
        data: Bytes::from_static(&[0xd5, 0xaa, 0xb2, 0x64]), // mintPublic selector
        access_list: Vec::new(),
    }
}

/// One wallet's real sign+serialize timing -- what `finalize_signed_transaction`
/// does, isolated from any RPC round trip.
fn sign_and_serialize_one(signer: &LocalSigner, nonce: u64) -> (Duration, Duration) {
    let unsigned = unsigned_tx_for(nonce);

    let sign_started = std::time::Instant::now();
    let signed = signer
        .sign_transaction(unsigned)
        .expect("local signing succeeds");
    let sign_elapsed = sign_started.elapsed();

    let serialize_started = std::time::Instant::now();
    let raw = signed.raw_bytes();
    let tx_hash = signed.tx_hash();
    let _prepared = PreparedBroadcast::build(tx_hash, raw);
    let serialize_elapsed = serialize_started.elapsed();

    (sign_elapsed, serialize_elapsed)
}

#[tokio::test]
#[ignore = "local benchmark, not a correctness test -- run explicitly with --ignored --nocapture"]
async fn public_sign_and_serialize_one_wallet() {
    let signer = signer_for("kairox-bench-sign-a");
    // One warm-up iteration so allocator/CPU-cache warm-up doesn't distort
    // the first real sample, matching how this actually runs in the
    // real pipeline (well after process startup, not the very first
    // ECDSA operation this process has ever performed).
    let _ = sign_and_serialize_one(&signer, 0);

    let (sign_ms, serialize_ms) = {
        let (s, r) = sign_and_serialize_one(&signer, 1);
        (s.as_secs_f64() * 1000.0, r.as_secs_f64() * 1000.0)
    };

    println!("=== LOCAL FRAMEWORK BENCHMARK (not real network latency) ===");
    println!("scenario: PUBLIC engine, 1 wallet, sign+serialize only (no RPC)");
    println!(
        "sign_ms={sign_ms:.3} serialize_ms={serialize_ms:.3} total_ms={:.3}",
        sign_ms + serialize_ms
    );

    // Both must be fast (sub-100ms on any real machine) and, crucially,
    // both must have actually completed -- proving there is nothing left
    // for the T=0 hot path to do once armed.
    assert!(sign_ms < 100.0, "sign took implausibly long: {sign_ms}ms");
    assert!(
        serialize_ms < 50.0,
        "serialize took implausibly long: {serialize_ms}ms"
    );
}

#[tokio::test]
#[ignore = "local benchmark, not a correctness test -- run explicitly with --ignored --nocapture"]
async fn public_sign_and_serialize_three_wallets() {
    let signers = [
        signer_for("kairox-bench-sign-a"),
        signer_for("kairox-bench-sign-b"),
        signer_for("kairox-bench-sign-c"),
    ];
    for s in &signers {
        let _ = sign_and_serialize_one(s, 0);
    }

    let started = std::time::Instant::now();
    let mut sign_total_ms = 0.0;
    let mut serialize_total_ms = 0.0;
    for s in &signers {
        let (sign, serialize) = sign_and_serialize_one(s, 1);
        sign_total_ms += sign.as_secs_f64() * 1000.0;
        serialize_total_ms += serialize.as_secs_f64() * 1000.0;
    }
    let wall_ms = started.elapsed().as_secs_f64() * 1000.0;

    println!("=== LOCAL FRAMEWORK BENCHMARK (not real network latency) ===");
    println!("scenario: PUBLIC engine, 3 legitimate wallets, sign+serialize only (no RPC)");
    println!(
        "sign_total_ms={sign_total_ms:.3} serialize_total_ms={serialize_total_ms:.3} wall_ms={wall_ms:.3}"
    );
    println!(
        "per-wallet average: sign_ms={:.3} serialize_ms={:.3}",
        sign_total_ms / 3.0,
        serialize_total_ms / 3.0
    );

    assert!(
        wall_ms < 300.0,
        "3-wallet sign+serialize took implausibly long: {wall_ms}ms"
    );
}
