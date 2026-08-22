//! A multi-endpoint RPC pool. Connecting the pool *is* Kairox's connection
//! pre-warming: DNS/TCP/TLS/HTTP state for every configured endpoint is
//! established (via the mandatory `eth_chainId` verification call) well
//! before any time-critical operation needs it, and the latency of that
//! first round trip is recorded per endpoint for reporting.

use std::time::{Duration, Instant};

use super::benchmark::{
    BenchmarkConfig, EndpointBenchmark, HealthPolicy, PrewarmReport, PrewarmStatus, SampleOutcome,
    benchmark_read_latency, select_read_endpoint, select_send_endpoints,
};
use super::endpoint::{EndpointRole, EndpointVerification, RpcEndpoint};
use super::registry::ChainId;
use super::rpc::{HttpTransport, RpcClient, RpcError, TransportError};

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
    /// The endpoint responded to `eth_chainId`, but reported a chain id
    /// other than the one it was configured under. Distinct from `Failed`
    /// (unreachable/no response) because this is a configuration mistake on
    /// a live endpoint, not a liveness problem.
    WrongChain {
        latency_ms: u64,
        expected: ChainId,
        reported: ChainId,
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
        Self::connect_all_with_transport(chain_id, endpoints, |endpoint| {
            Box::new(HttpTransport::new(endpoint.url.clone(), endpoint.timeout))
        })
        .await
    }

    /// Same as [`Self::connect_all`], but builds each endpoint's transport
    /// via `make_transport` instead of always constructing a real
    /// [`HttpTransport`]. Exists so tests can exercise the full
    /// `connect_all` classification path (including [`ConnectOutcome`]
    /// variants like `WrongChain`) with a [`super::mock::MockTransport`],
    /// without a heavier mock-HTTP-server dependency or distorting the
    /// production `connect_all` signature.
    async fn connect_all_with_transport(
        chain_id: ChainId,
        endpoints: &[RpcEndpoint],
        make_transport: impl Fn(&RpcEndpoint) -> Box<dyn super::rpc::Transport>,
    ) -> (Self, Vec<EndpointConnectReport>) {
        let make_transport = &make_transport;
        let attempts = endpoints.iter().map(|endpoint| async move {
            let started = Instant::now();
            let transport = make_transport(endpoint);
            let result =
                RpcClient::connect(transport, chain_id, endpoint.role, endpoint.label.clone())
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
                Err(super::rpc::RpcError::ChainIdMismatch { expected, reported }) => {
                    reports.push(EndpointConnectReport {
                        label: endpoint.label.clone(),
                        role: endpoint.role,
                        outcome: ConnectOutcome::WrongChain {
                            latency_ms,
                            expected,
                            reported,
                        },
                    })
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

    /// Near-T0 rewarm: refresh liveness on already-connected clients ahead
    /// of a mint attempt.
    ///
    /// This is distinct from [`Self::connect_all`], which performs the
    /// *initial* connection/discovery (DNS/TCP/TLS + the mandatory
    /// `eth_chainId` verification that decides each endpoint's trust
    /// classification). `rewarm_all` never changes an endpoint's trust
    /// classification — it only refreshes liveness signal for endpoints
    /// already admitted to the pool, using the same safe-probe rules
    /// throughout: a fresh `eth_blockNumber` sample for read-capable
    /// endpoints, a reused `eth_chainId` call for chain-id-verified
    /// send-capable endpoints, and — critically — no call at all for a
    /// genuine [`EndpointVerification::ConfiguredSendOnly`] endpoint, since
    /// its only exposed method is `eth_sendRawTransaction` and Kairox never
    /// sends a fake/dummy transaction merely to warm a connection.
    ///
    /// A successful read-capable rewarm records its latency in
    /// `prewarm_latency_ms` only — it never touches `read_latency`, which
    /// stays owned by [`Self::benchmark_all`]'s repeated-sample statistics
    /// (median/p90/p95) used for ranking. Overwriting those with a single
    /// fresh sample would silently destroy Phase 3's statistical endpoint
    /// ranking every time a mint runs. A failed rewarm for any probed
    /// endpoint marks it unhealthy for both read and send selection via
    /// `prewarm_status`, so a fresh failure is never silently reported as
    /// healthy — but a *successful* rewarm never overwrites the existing
    /// ranking data either.
    ///
    /// For a `VerifiedSend` endpoint, the reused `eth_chainId` probe is not
    /// merely "did it respond" — the reported chain id must still match
    /// this pool's chain id. An endpoint that unexpectedly reports a
    /// different chain during rewarm is treated exactly like a failed
    /// probe (`Failed`, excluded from send selection): trust classification
    /// itself is never re-run here (only [`RpcClient::connect`] does that),
    /// but a rewarm can and must still detect an endpoint gone unsafe to
    /// use *right now*.
    pub async fn rewarm_all(&mut self) -> Vec<PrewarmReport> {
        let expected_chain_id = self.chain_id;
        // Every endpoint's probe runs concurrently (mirrors `connect_all`
        // and `benchmark_all`): `run_live_mint` times this call's wall-clock
        // duration as `prewarm_ms`, and a sum of sequential per-endpoint
        // probe times would misrepresent that as far slower than it
        // actually is.
        let outcomes =
            futures_util::future::join_all(self.clients.iter().zip(self.benchmarks.iter()).map(
                |(client, bench)| async move {
                    let label = client.label().map(str::to_string);

                    if bench.verification == EndpointVerification::ConfiguredSendOnly {
                        return (label, PrewarmStatus::UnavailableForSubmissionOnly, None);
                    }

                    if client.role().can_read() {
                        let started = Instant::now();
                        let outcome = match client.block_number().await {
                            Ok(_) => SampleOutcome::Ok(duration_ms(started.elapsed())),
                            Err(RpcError::Transport(TransportError::Timeout(_))) => {
                                SampleOutcome::Timeout
                            }
                            Err(_) => SampleOutcome::Error,
                        };
                        let status = if matches!(outcome, SampleOutcome::Ok(_)) {
                            PrewarmStatus::Warmed
                        } else {
                            PrewarmStatus::Failed
                        };
                        let latency_ms = match outcome {
                            SampleOutcome::Ok(ms) => Some(ms),
                            _ => None,
                        };
                        return (label, status, latency_ms);
                    }

                    // Chain-id-verified, send-capable, not read-capable
                    // (`VerifiedSend`): reuse the same `eth_chainId`
                    // capability call as a liveness probe, but require the
                    // reported chain id to still match -- a bare `Ok(_)` is
                    // not enough. This never re-runs trust classification
                    // -- only `RpcClient::connect` does that.
                    let started = Instant::now();
                    let status = match client.chain_id().await {
                        Ok(reported) if reported == expected_chain_id => PrewarmStatus::Warmed,
                        Ok(_) | Err(_) => PrewarmStatus::Failed,
                    };
                    let latency_ms = matches!(status, PrewarmStatus::Warmed)
                        .then(|| duration_ms(started.elapsed()));
                    (label, status, latency_ms)
                },
            ))
            .await;

        let mut reports = Vec::with_capacity(outcomes.len());
        for ((label, status, latency_ms), bench) in
            outcomes.into_iter().zip(self.benchmarks.iter_mut())
        {
            bench.prewarm_latency_ms = latency_ms;
            bench.prewarm_status = Some(status);
            reports.push(PrewarmReport {
                label,
                status,
                latency_ms,
            });
        }
        reports
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
    async fn connect_all_rejects_genuinely_dead_sequencer_url_via_chain_config() {
        use super::super::endpoint::RpcEndpoint;
        use url::Url;

        // "sequencer.example" is a reserved, guaranteed-non-resolving domain
        // (RFC 2606) -> this is a real, end-to-end proof that a Sequencer
        // role alone is never enough to admit a dead endpoint into the pool.
        // It must be rejected as unreachable, never accepted as
        // ConfiguredSendOnly, even though it was explicitly configured under
        // chain id 4663.
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
        assert_eq!(
            pool.len(),
            0,
            "a dead sequencer URL must not enter the pool"
        );
        assert!(pool.send_capable().is_empty());
        assert!(pool.read_capable().is_empty());

        match &reports[0].outcome {
            ConnectOutcome::Failed { .. } => {}
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submission_only_endpoint_present_but_no_read_capable_endpoint() {
        let sequencer_transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .build();
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
    async fn benchmark_all_never_probes_a_send_only_endpoint_with_a_read_call() {
        // A send-only (sequencer) transport that has no `eth_blockNumber`
        // responder configured at all -- if `benchmark_all` ever issued a
        // read probe against it despite the missing responder, the sample
        // would still land as `Some(LatencyStats)` (recorded as a
        // failure/timeout, never silently dropped), so `read_latency`
        // staying `None` below is proof the probe was never attempted at
        // all, not just that it failed.
        let send_only_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let send_only = RpcClient::connect(
            Box::new(send_only_transport),
            1,
            EndpointRole::SendOnly,
            Some("sequencer".into()),
        )
        .await
        .unwrap();

        let mut pool = RpcPool::from_clients(1, vec![send_only]);
        pool.benchmark_all(&super::super::benchmark::BenchmarkConfig {
            sample_count: 3,
            sample_delay: Duration::ZERO,
        })
        .await;

        assert!(
            pool.benchmarks()[0].read_latency.is_none(),
            "a send-only endpoint must never receive a read-latency sample"
        );
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

    #[tokio::test]
    async fn connect_all_reports_wrong_chain_directly_via_injected_mock_transport() {
        use super::super::endpoint::RpcEndpoint;
        use url::Url;

        let endpoint = RpcEndpoint::new(
            Url::parse("https://mismatched.example").unwrap(),
            EndpointRole::ReadOnly,
        )
        .with_label("mismatched");

        let (pool, reports) = RpcPool::connect_all_with_transport(4663, &[endpoint], |_| {
            Box::new(
                MockTransport::builder()
                    .respond("eth_chainId", json!("0x1"))
                    .build(),
            )
        })
        .await;

        assert_eq!(
            pool.len(),
            0,
            "a wrong-chain endpoint must not enter the pool"
        );
        match &reports[0].outcome {
            ConnectOutcome::WrongChain {
                expected, reported, ..
            } => {
                assert_eq!(*expected, 4663);
                assert_eq!(*reported, 1);
            }
            other => panic!("expected WrongChain, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rewarm_all_warms_read_capable_endpoint_via_block_number() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x2a"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let mut pool = RpcPool::from_clients(1, vec![client]);

        let reports = pool.rewarm_all().await;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].status, PrewarmStatus::Warmed);
        assert_eq!(
            pool.benchmarks()[0].prewarm_status,
            Some(PrewarmStatus::Warmed)
        );
        // A rewarm probe's latency is recorded separately from
        // `read_latency` -- which stays whatever `benchmark_all` last set
        // it to (`None` here, since this pool was never benchmarked).
        assert!(pool.benchmarks()[0].prewarm_latency_ms.is_some());
        assert!(pool.benchmarks()[0].read_latency.is_none());
    }

    #[tokio::test]
    async fn rewarm_all_never_destroys_multi_sample_benchmark_statistics() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x2a"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let mut pool = RpcPool::from_clients(1, vec![client]);
        pool.benchmark_all(&BenchmarkConfig {
            sample_count: 5,
            sample_delay: Duration::ZERO,
        })
        .await;

        let before = pool.benchmarks()[0].read_latency.expect("benchmarked");
        assert_eq!(before.sample_count, 5);
        assert!(before.median_ms.is_some());
        assert!(before.p90_ms.is_some());
        assert!(before.p95_ms.is_some());

        pool.rewarm_all().await;

        let after = pool.benchmarks()[0]
            .read_latency
            .expect("rewarm must not clear benchmark data");
        assert_eq!(
            after, before,
            "a successful rewarm must never overwrite the richer multi-sample benchmark statistics"
        );
        assert_eq!(
            after.sample_count, 5,
            "a 5-sample benchmark must remain a 5-sample benchmark after rewarming"
        );
        assert!(
            pool.benchmarks()[0].prewarm_latency_ms.is_some(),
            "the rewarm probe's own latency must still be recorded separately"
        );
    }

    #[tokio::test]
    async fn rewarm_all_rejects_verified_send_endpoint_that_now_reports_a_different_chain() {
        // First `eth_chainId` call (during `connect`) reports chain 1,
        // matching the pool -> VerifiedSend. The second call (during
        // `rewarm_all`) reports chain 2, simulating an endpoint that has
        // been silently rerouted/misconfigured since it was connected.
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_for_closure = call_count.clone();
        let transport = MockTransport::builder()
            .respond_dynamic("eth_chainId", move |_params| {
                let n = call_count_for_closure.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 { json!("0x1") } else { json!("0x2") }
            })
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        assert_eq!(client.verification(), EndpointVerification::VerifiedSend);
        let mut pool = RpcPool::from_clients(1, vec![client]);

        let reports = pool.rewarm_all().await;
        assert_eq!(
            reports[0].status,
            PrewarmStatus::Failed,
            "an endpoint that now reports a different chain must never be treated as warmed"
        );
        let bench = &pool.benchmarks()[0];
        assert_eq!(bench.prewarm_status, Some(PrewarmStatus::Failed));
        assert!(
            !bench.is_healthy_for_send(&HealthPolicy::default()),
            "an endpoint that reported a different chain on rewarm must never remain send-eligible"
        );
    }

    #[tokio::test]
    async fn rewarm_all_marks_verified_send_endpoint_warmed_via_chain_id_reuse() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        let mut pool = RpcPool::from_clients(1, vec![client]);

        let reports = pool.rewarm_all().await;
        assert_eq!(reports[0].status, PrewarmStatus::Warmed);
        // Send-only, non-read role -> no read_latency is ever populated.
        assert!(pool.benchmarks()[0].read_latency.is_none());
    }

    #[tokio::test]
    async fn rewarm_all_never_probes_genuine_configured_send_only_endpoint() {
        let transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        let mut pool = RpcPool::from_clients(1, vec![client]);

        let reports = pool.rewarm_all().await;
        assert_eq!(
            reports[0].status,
            PrewarmStatus::UnavailableForSubmissionOnly
        );
        assert_eq!(
            pool.benchmarks()[0].prewarm_status,
            Some(PrewarmStatus::UnavailableForSubmissionOnly)
        );
    }

    #[tokio::test]
    async fn rewarm_all_marks_failed_read_probe_and_excludes_from_health() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .error("eth_blockNumber", -32000, "boom")
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap();
        let mut pool = RpcPool::from_clients(1, vec![client]);

        let reports = pool.rewarm_all().await;
        assert_eq!(reports[0].status, PrewarmStatus::Failed);
        let bench = &pool.benchmarks()[0];
        assert_eq!(bench.prewarm_status, Some(PrewarmStatus::Failed));
        let policy = HealthPolicy::default();
        assert!(
            !bench.is_healthy_for_read(&policy),
            "a fresh prewarm failure must never be silently reported as healthy"
        );
        assert!(
            !bench.is_healthy_for_send(&policy),
            "a fresh prewarm failure must exclude the endpoint from send selection too"
        );
    }

    /// Round 6 item 3G / the "T-30 fastest, T0 dead" scenario, on one
    /// consistent pool/client (not a fresh reconnect): endpoint A answers
    /// `eth_blockNumber` successfully for its early full-benchmark samples,
    /// then starts failing every call from the near-T0 rewarm onward --
    /// exactly what a real endpoint going down between an early benchmark
    /// and T0 looks like. B stays healthy throughout, just slower.
    /// Selection must not blindly trust A's now-stale fast ranking; it
    /// must fail A closed and select B, the currently-healthy endpoint.
    #[tokio::test]
    async fn a_formerly_fastest_endpoint_that_dies_before_t0_loses_selection_to_a_healthy_endpoint()
    {
        use super::super::benchmark::BenchmarkConfig;
        use std::sync::atomic::{AtomicU32, Ordering};

        const FULL_BENCHMARK_SAMPLES: u32 = 3;
        let a_call_count = std::sync::Arc::new(AtomicU32::new(0));
        let a_call_count_for_closure = a_call_count.clone();
        let a_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond_dynamic_result("eth_blockNumber", move |_params| {
                let n = a_call_count_for_closure.fetch_add(1, Ordering::SeqCst);
                if n < FULL_BENCHMARK_SAMPLES {
                    Ok(json!("0x1"))
                } else {
                    Err((-32000, "connection reset".to_string()))
                }
            })
            .build();
        let a = RpcClient::connect(
            Box::new(a_transport),
            1,
            EndpointRole::ReadOnly,
            Some("a-formerly-fastest".into()),
        )
        .await
        .unwrap();

        // B: slower at the early full benchmark (an added delay), but
        // healthy throughout, including at rewarm time.
        let b_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .delay("eth_blockNumber", Duration::from_millis(20))
            .build();
        let b = RpcClient::connect(
            Box::new(b_transport),
            1,
            EndpointRole::ReadOnly,
            Some("b-formerly-slower".into()),
        )
        .await
        .unwrap();

        let mut pool = RpcPool::from_clients(1, vec![a, b]);
        pool.benchmark_all(&BenchmarkConfig {
            sample_count: FULL_BENCHMARK_SAMPLES,
            sample_delay: Duration::ZERO,
        })
        .await;

        // Confirm the early ranking really did prefer A -- otherwise this
        // test would trivially pass for the wrong reason.
        assert_eq!(
            pool.preferred_read().unwrap().label(),
            Some("a-formerly-fastest"),
            "sanity check: the early benchmark must have actually ranked A first"
        );

        // T0 approaches: the near-T0 rewarm is the only thing that runs
        // again before dispatch, and A now fails every call.
        pool.rewarm_all().await;

        let selected = pool.preferred_read();
        assert_eq!(
            selected.map(|c| c.label()),
            Some(Some("b-formerly-slower")),
            "a dead endpoint must never be selected merely because it was ranked fastest \
             at an earlier point in time; the currently-healthy endpoint must be chosen"
        );
    }
}
