//! A multi-endpoint RPC pool. Connecting the pool *is* Kairox's connection
//! pre-warming: DNS/TCP/TLS/HTTP state for every configured endpoint is
//! established (via the mandatory `eth_chainId` verification call) well
//! before any time-critical operation needs it, and the latency of that
//! first round trip is recorded per endpoint for reporting.

use std::time::{Duration, Instant};

use super::benchmark::{
    BenchmarkConfig, EndpointBenchmark, HealthPolicy, benchmark_read_latency, select_read_endpoint,
    select_send_endpoints,
};
use super::endpoint::{EndpointRole, EndpointVerification, RpcEndpoint};
use super::registry::ChainId;
use super::rpc::{HttpTransport, RpcClient};

/// Per-endpoint outcome of connecting (and thereby pre-warming) one entry
/// in a [`RpcPool`].
#[derive(Debug, Clone)]
pub struct EndpointConnectReport {
    pub label: Option<String>,
    pub role: EndpointRole,
    pub outcome: ConnectOutcome,
}

#[derive(Debug, Clone)]
pub enum ConnectOutcome {
    Connected {
        latency_ms: u64,
        verification: EndpointVerification,
    },
    Failed {
        latency_ms: u64,
        error: String,
    },
}

/// A set of chain-id-verified, pre-warmed RPC clients for one chain, with
/// (optionally populated) per-endpoint benchmark data.
pub struct RpcPool {
    chain_id: ChainId,
    clients: Vec<RpcClient>,
    /// Parallel to `clients`. Always present (never `None`) — a
    /// not-yet-benchmarked endpoint simply has `read_latency: None`, which
    /// [`Self::preferred_read`] treats as "no benchmark data yet" and falls
    /// back to Phase 2's original first-read-capable behavior for.
    benchmarks: Vec<EndpointBenchmark>,
}

impl RpcPool {
    /// Build a pool directly from already-connected clients. Used by tests
    /// (with mock transports) and by [`Self::connect_all`].
    pub fn from_clients(chain_id: ChainId, clients: Vec<RpcClient>) -> Self {
        let benchmarks = clients.iter().map(EndpointBenchmark::initial).collect();
        Self {
            chain_id,
            clients,
            benchmarks,
        }
    }

    /// Connect every configured endpoint concurrently over real HTTP,
    /// verifying `eth_chainId` for each. Endpoints that fail to connect
    /// (wrong chain, timeout, network error) are excluded from the pool but
    /// reported individually — a partially healthy pool is still usable as
    /// long as it has at least one endpoint of the role a caller needs.
    /// This connection attempt *is* Kairox's connection pre-warming; its
    /// latency seeds each surviving client's `connection_latency_ms`.
    pub async fn connect_all(
        chain_id: ChainId,
        endpoints: &[RpcEndpoint],
    ) -> (Self, Vec<EndpointConnectReport>) {
        let attempts = endpoints.iter().map(|endpoint| async move {
            let started = Instant::now();
            let transport = HttpTransport::new(endpoint.url.clone(), endpoint.timeout);
            let result = RpcClient::connect(
                Box::new(transport),
                chain_id,
                endpoint.role,
                endpoint.label.clone(),
            )
            .await;
            (endpoint, started.elapsed(), result)
        });

        let results = futures_util::future::join_all(attempts).await;

        let mut clients = Vec::new();
        let mut connect_latencies = Vec::new();
        let mut reports = Vec::new();
        for (endpoint, elapsed, result) in results {
            let latency_ms = duration_ms(elapsed);
            match result {
                Ok(client) => {
                    reports.push(EndpointConnectReport {
                        label: endpoint.label.clone(),
                        role: endpoint.role,
                        outcome: ConnectOutcome::Connected {
                            latency_ms,
                            verification: client.verification(),
                        },
                    });
                    connect_latencies.push(latency_ms);
                    clients.push(client);
                }
                Err(e) => reports.push(EndpointConnectReport {
                    label: endpoint.label.clone(),
                    role: endpoint.role,
                    outcome: ConnectOutcome::Failed {
                        latency_ms,
                        error: e.to_string(),
                    },
                }),
            }
        }

        let mut pool = Self::from_clients(chain_id, clients);
        for (bench, latency_ms) in pool.benchmarks.iter_mut().zip(connect_latencies) {
            bench.connection_latency_ms = Some(latency_ms);
        }

        (pool, reports)
    }

    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Every client whose role permits state reads.
    pub fn read_capable(&self) -> Vec<&RpcClient> {
        self.clients
            .iter()
            .filter(|c| c.role().can_read())
            .collect()
    }

    /// Every client whose role permits broadcasting, unfiltered by health —
    /// Phase 2's original behavior, preserved exactly. Use
    /// [`Self::select_send_endpoints`] for the health-filtered Phase 3
    /// broadcast candidate list.
    pub fn send_capable(&self) -> Vec<&RpcClient> {
        self.clients
            .iter()
            .filter(|c| c.role().can_send())
            .collect()
    }

    /// Take bounded, repeated latency samples of every read-capable client
    /// and store the results. Safe to call multiple times (each call
    /// replaces prior read-latency data); never touches send-only/
    /// `ConfiguredSendOnly` clients, and never broadcasts anything.
    pub async fn benchmark_all(&mut self, config: &BenchmarkConfig) {
        let samples =
            futures_util::future::join_all(self.clients.iter().map(|client| async move {
                if client.role().can_read() {
                    Some(benchmark_read_latency(client, config).await)
                } else {
                    None
                }
            }))
            .await;

        for (bench, read_latency) in self.benchmarks.iter_mut().zip(samples) {
            bench.read_latency = read_latency;
        }
    }

    /// The current benchmark record for every client, in the same order as
    /// the pool's clients.
    pub fn benchmarks(&self) -> &[EndpointBenchmark] {
        &self.benchmarks
    }

    fn paired(&self) -> Vec<(&RpcClient, &EndpointBenchmark)> {
        self.clients_with_benchmarks().collect()
    }

    /// Every client paired with its current benchmark record, in pool
    /// order. Prefer comparing the returned `&RpcClient` by identity
    /// (`std::ptr::eq`) rather than by label when matching against
    /// [`Self::preferred_read`]/[`Self::select_send_endpoints`] results —
    /// labels are operator-supplied and may be absent or repeated.
    pub fn clients_with_benchmarks(
        &self,
    ) -> impl Iterator<Item = (&RpcClient, &EndpointBenchmark)> {
        self.clients.iter().zip(self.benchmarks.iter())
    }

    /// The single best read-capable, chain-verified, healthy client by
    /// lowest median latency, deterministic on ties.
    ///
    /// Falls back to Phase 2's original "first read-capable client"
    /// behavior only when [`Self::benchmark_all`] was never called at all
    /// (no benchmark data exists yet) — existing callers that never
    /// benchmark keep working unchanged. Once benchmarking *has* run, an
    /// empty result means every read-capable candidate failed the health
    /// policy, and this fails closed (`None`) rather than silently falling
    /// back to a known-unhealthy endpoint.
    pub fn preferred_read(&self) -> Option<&RpcClient> {
        let benchmarked = self.benchmarks.iter().any(|b| b.read_latency.is_some());
        let selected = select_read_endpoint(&self.paired(), &HealthPolicy::default());
        if selected.is_some() || benchmarked {
            return selected;
        }
        self.read_capable().into_iter().next()
    }

    /// The health-filtered, deterministically-ordered broadcast candidate
    /// list. When no benchmark data exists yet, every send-capable client
    /// is included (nothing to exclude on) — equivalent to
    /// [`Self::send_capable`] in that case.
    pub fn select_send_endpoints(&self, policy: &HealthPolicy) -> Vec<&RpcClient> {
        select_send_endpoints(&self.paired(), policy)
    }
}

fn duration_ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::super::rpc::RpcError;
    use super::*;
    use crate::chain::mock::MockTransport;
    use serde_json::json;

    async fn mock_client(
        chain_id: ChainId,
        role: EndpointRole,
        reported_chain_id: u64,
    ) -> RpcClient {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!(format!("0x{reported_chain_id:x}")))
            .build();
        RpcClient::connect(Box::new(transport), chain_id, role, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn pool_partitions_read_and_send_capable_clients() {
        let read_only = mock_client(1, EndpointRole::ReadOnly, 1).await;
        let send_only = mock_client(1, EndpointRole::SendOnly, 1).await;
        let read_write = mock_client(1, EndpointRole::ReadWrite, 1).await;

        let pool = RpcPool::from_clients(1, vec![read_only, send_only, read_write]);

        assert_eq!(pool.len(), 3);
        assert_eq!(pool.read_capable().len(), 2, "read-only + read-write");
        assert_eq!(pool.send_capable().len(), 2, "send-only + read-write");
    }

    #[tokio::test]
    async fn send_only_endpoint_excluded_from_read_capable() {
        let send_only = mock_client(1, EndpointRole::SendOnly, 1).await;
        let pool = RpcPool::from_clients(1, vec![send_only]);
        assert!(pool.read_capable().is_empty());
        assert_eq!(pool.send_capable().len(), 1);
    }

    #[tokio::test]
    async fn read_only_endpoint_excluded_from_send_capable() {
        let read_only = mock_client(1, EndpointRole::ReadOnly, 1).await;
        let pool = RpcPool::from_clients(1, vec![read_only]);
        assert!(pool.send_capable().is_empty());
        assert_eq!(pool.read_capable().len(), 1);
    }

    #[tokio::test]
    async fn connect_all_excludes_wrong_chain_endpoint_and_reports_it() {
        let good_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let good_client = RpcClient::connect(
            Box::new(good_transport),
            1,
            EndpointRole::ReadOnly,
            Some("good".into()),
        )
        .await
        .unwrap();

        // Simulate connect_all's per-endpoint behavior directly: one client
        // that matches, one report representing a mismatched endpoint that
        // never made it into the pool.
        let pool = RpcPool::from_clients(1, vec![good_client]);
        assert_eq!(pool.len(), 1);

        let mismatched_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x2"))
            .build();
        let err = RpcClient::connect(
            Box::new(mismatched_transport),
            1,
            EndpointRole::ReadOnly,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RpcError::ChainIdMismatch { .. }));
    }

    #[tokio::test]
    async fn preferred_read_returns_first_read_capable_client() {
        let send_only = mock_client(1, EndpointRole::SendOnly, 1).await;
        let read_only = mock_client(1, EndpointRole::ReadOnly, 1).await;
        let pool = RpcPool::from_clients(1, vec![send_only, read_only]);
        let preferred = pool.preferred_read().unwrap();
        assert_eq!(preferred.role(), EndpointRole::ReadOnly);
    }

    #[tokio::test]
    async fn empty_pool_reports_empty() {
        let pool = RpcPool::from_clients(1, vec![]);
        assert!(pool.is_empty());
        assert!(pool.preferred_read().is_none());
    }

    #[tokio::test]
    async fn connect_all_accepts_submission_only_endpoint_and_binds_it_via_chain_config() {
        use super::super::endpoint::{EndpointVerification, RpcEndpoint};
        use url::Url;

        // No eth_chainId configured at all -> simulates a genuine
        // submission-only sequencer ingress. It is still accepted because
        // it was explicitly configured under chain id 4663.
        let endpoint = RpcEndpoint::new(
            Url::parse("https://sequencer.example").unwrap(),
            EndpointRole::Sequencer,
        )
        .with_label("robinhood-sequencer");

        let (pool, reports) = RpcPool::connect_all(4663, &[endpoint]).await;

        assert_eq!(
            pool.chain_id(),
            4663,
            "binding comes only from the chain-scoped config call"
        );
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.send_capable().len(), 1);
        assert!(pool.read_capable().is_empty());

        match &reports[0].outcome {
            ConnectOutcome::Connected { verification, .. } => {
                assert_eq!(*verification, EndpointVerification::ConfiguredSendOnly);
            }
            other => panic!("expected Connected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submission_only_endpoint_present_but_no_read_capable_endpoint() {
        let sequencer_transport = MockTransport::builder().build();
        let sequencer = RpcClient::connect(
            Box::new(sequencer_transport),
            1,
            EndpointRole::Sequencer,
            Some("seq".into()),
        )
        .await
        .unwrap();

        let pool = RpcPool::from_clients(1, vec![sequencer]);
        assert!(!pool.send_capable().is_empty());
        assert!(
            pool.preferred_read().is_none(),
            "a ConfiguredSendOnly-only pool must never report a usable read client"
        );
    }

    #[tokio::test]
    async fn preferred_read_uses_benchmark_data_once_benchmarked() {
        use super::super::benchmark::BenchmarkConfig;

        let fast_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .build();
        let fast = RpcClient::connect(
            Box::new(fast_transport),
            1,
            EndpointRole::ReadOnly,
            Some("fast".into()),
        )
        .await
        .unwrap();

        let slow_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .delay("eth_blockNumber", Duration::from_millis(20))
            .build();
        let slow = RpcClient::connect(
            Box::new(slow_transport),
            1,
            EndpointRole::ReadOnly,
            Some("slow".into()),
        )
        .await
        .unwrap();

        let mut pool = RpcPool::from_clients(1, vec![slow, fast]);
        pool.benchmark_all(&BenchmarkConfig {
            sample_count: 3,
            sample_delay: Duration::ZERO,
        })
        .await;

        let selected = pool.preferred_read().unwrap();
        assert_eq!(selected.label(), Some("fast"));
    }

    #[tokio::test]
    async fn preferred_read_fails_closed_when_benchmarked_and_all_unhealthy() {
        use super::super::benchmark::BenchmarkConfig;

        let dead_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .error("eth_blockNumber", -32000, "boom")
            .build();
        let dead = RpcClient::connect(Box::new(dead_transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();

        let mut pool = RpcPool::from_clients(1, vec![dead]);
        pool.benchmark_all(&BenchmarkConfig {
            sample_count: 3,
            sample_delay: Duration::ZERO,
        })
        .await;

        assert!(
            pool.preferred_read().is_none(),
            "must fail closed rather than silently fall back to a benchmarked-unhealthy endpoint"
        );
    }

    #[tokio::test]
    async fn select_send_endpoints_matches_send_capable_before_benchmarking() {
        let a = mock_client(1, EndpointRole::SendOnly, 1).await;
        let pool = RpcPool::from_clients(1, vec![a]);
        assert_eq!(
            pool.select_send_endpoints(&super::super::benchmark::HealthPolicy::default())
                .len(),
            pool.send_capable().len()
        );
    }

    #[tokio::test]
    async fn clients_with_benchmarks_supports_identity_based_selection_matching_with_unlabeled_endpoints()
     {
        use super::super::benchmark::BenchmarkConfig;

        // Two endpoints, neither labeled — a naive label-based join would
        // be unable to tell them apart (this was a real bug: comparing
        // `RpcClient::label()` against a display-only "(unlabeled)"
        // placeholder). Identity (pointer) comparison must still work.
        let fast_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .build();
        let fast = RpcClient::connect(Box::new(fast_transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();

        let slow_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .delay("eth_blockNumber", Duration::from_millis(20))
            .build();
        let slow = RpcClient::connect(Box::new(slow_transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();

        let mut pool = RpcPool::from_clients(1, vec![slow, fast]);
        pool.benchmark_all(&BenchmarkConfig {
            sample_count: 3,
            sample_delay: Duration::ZERO,
        })
        .await;

        let selected_ptr = pool.preferred_read().map(std::ptr::from_ref);
        let mut matches = 0;
        for (client, _bench) in pool.clients_with_benchmarks() {
            if Some(std::ptr::from_ref(client)) == selected_ptr {
                matches += 1;
            }
        }
        assert_eq!(
            matches, 1,
            "identity comparison must uniquely match exactly the selected client"
        );
    }
}
