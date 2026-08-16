//! Endpoint latency benchmarking, health scoring, and deterministic
//! read/send endpoint selection.
//!
//! Kairox never fakes a benchmark number: a send-only-capable endpoint that
//! cannot safely be probed (it only implements `eth_sendRawTransaction`)
//! reports [`BroadcastLatency::UnknownUntilRealAttempt`] rather than an
//! invented figure, and is never sampled with a real transaction merely to
//! measure it.

use std::time::{Duration, Instant};

use super::endpoint::{EndpointRole, EndpointVerification};
use super::rpc::{RpcClient, RpcError, TransportError};

/// The outcome of one latency sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleOutcome {
    Ok(u64),
    Timeout,
    Error,
}

/// How many bounded samples to take per read-capable endpoint, and how long
/// to wait between them. Deliberately conservative defaults — Kairox must
/// never hammer a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchmarkConfig {
    pub sample_count: u32,
    pub sample_delay: Duration,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            sample_count: 5,
            sample_delay: Duration::from_millis(50),
        }
    }
}

/// Aggregate latency statistics computed from a bounded, fixed-size sample
/// set. Deliberately simple — sample count, min/max/mean/median/p90/p95,
/// and failure/timeout counts are enough to make a safe selection decision
/// without over-modeling noisy network data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyStats {
    pub sample_count: u32,
    pub successes: u32,
    pub failures: u32,
    pub timeouts: u32,
    pub min_ms: Option<u64>,
    pub max_ms: Option<u64>,
    pub mean_ms: Option<u64>,
    pub median_ms: Option<u64>,
    pub p90_ms: Option<u64>,
    pub p95_ms: Option<u64>,
}

impl LatencyStats {
    pub fn from_samples(samples: &[SampleOutcome]) -> Self {
        let mut ok: Vec<u64> = samples
            .iter()
            .filter_map(|s| match s {
                SampleOutcome::Ok(ms) => Some(*ms),
                _ => None,
            })
            .collect();
        ok.sort_unstable();

        let failures = samples
            .iter()
            .filter(|s| matches!(s, SampleOutcome::Error))
            .count() as u32;
        let timeouts = samples
            .iter()
            .filter(|s| matches!(s, SampleOutcome::Timeout))
            .count() as u32;

        let min_ms = ok.first().copied();
        let max_ms = ok.last().copied();
        let mean_ms = if ok.is_empty() {
            None
        } else {
            Some(ok.iter().sum::<u64>() / ok.len() as u64)
        };

        Self {
            sample_count: samples.len() as u32,
            successes: ok.len() as u32,
            failures,
            timeouts,
            min_ms,
            max_ms,
            mean_ms,
            median_ms: percentile(&ok, 50.0),
            p90_ms: percentile(&ok, 90.0),
            p95_ms: percentile(&ok, 95.0),
        }
    }

    pub fn timeout_rate(&self) -> f64 {
        if self.sample_count == 0 {
            return 0.0;
        }
        f64::from(self.timeouts) / f64::from(self.sample_count)
    }

    pub fn failure_rate(&self) -> f64 {
        if self.sample_count == 0 {
            return 0.0;
        }
        f64::from(self.failures) / f64::from(self.sample_count)
    }
}

/// Nearest-rank percentile over an already-sorted, successes-only sample
/// vector. `None` when there is no successful sample at all.
fn percentile(sorted_ok: &[u64], pct: f64) -> Option<u64> {
    if sorted_ok.is_empty() {
        return None;
    }
    let rank = ((pct / 100.0) * (sorted_ok.len() as f64 - 1.0)).round() as usize;
    sorted_ok.get(rank.min(sorted_ok.len() - 1)).copied()
}

/// Whether — and how — a send-capable endpoint's broadcast latency could be
/// known. Kairox never sends a real transaction merely to benchmark one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastLatency {
    /// This endpoint's role does not permit broadcasting at all.
    NotApplicable,
    /// This endpoint can broadcast, but Kairox has (and will) never send a
    /// real transaction just to measure it — genuinely unknown until a real
    /// mint attempt happens.
    UnknownUntilRealAttempt,
}

/// A complete, inspectable benchmark record for one endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointBenchmark {
    /// Mirrors [`RpcClient::label`] exactly (including `None`) so callers
    /// can match a benchmark record back to a selected `&RpcClient` by
    /// comparing labels without a lossy "(unlabeled)" placeholder on only
    /// one side of the comparison.
    pub label: Option<String>,
    pub role: EndpointRole,
    pub verification: EndpointVerification,
    /// Latency of the initial connect/verification round trip, if this
    /// benchmark was seeded from a [`super::pool::RpcPool::connect_all`]
    /// report.
    pub connection_latency_ms: Option<u64>,
    /// Repeated-sample read latency. `None` when the endpoint's role does
    /// not permit reads at all — never a fabricated value.
    pub read_latency: Option<LatencyStats>,
    pub broadcast_latency: BroadcastLatency,
}

impl EndpointBenchmark {
    /// A fresh, not-yet-sampled record for `client`. `connection_latency_ms`
    /// is filled in separately by whoever connected the client.
    pub fn initial(client: &RpcClient) -> Self {
        Self {
            label: client.label().map(str::to_string),
            role: client.role(),
            verification: client.verification(),
            connection_latency_ms: None,
            read_latency: None,
            broadcast_latency: if client.role().can_send() {
                BroadcastLatency::UnknownUntilRealAttempt
            } else {
                BroadcastLatency::NotApplicable
            },
        }
    }

    /// Whether this endpoint's health data clears `policy` for state reads.
    /// Roles that cannot read at all are never eligible, regardless of any
    /// (impossible) latency data attached to them.
    pub fn is_healthy_for_read(&self, policy: &HealthPolicy) -> bool {
        if !self.role.can_read() {
            return false;
        }
        match &self.read_latency {
            Some(stats) if stats.sample_count > 0 => {
                stats.timeout_rate() <= policy.max_timeout_rate
                    && stats.failure_rate() <= policy.max_failure_rate
                    && stats.successes > 0
            }
            _ => false,
        }
    }

    /// Whether this endpoint should remain a broadcast candidate. Send-only
    /// endpoints Kairox has no safe read signal for are always included —
    /// excluding them would remove a genuinely independent propagation
    /// path based on data that doesn't exist. An endpoint that *does* have
    /// read data (e.g. a `READ_WRITE` node) showing it is clearly dead is
    /// excluded even from sending.
    pub fn is_healthy_for_send(&self, policy: &HealthPolicy) -> bool {
        if !self.role.can_send() {
            return false;
        }
        match &self.read_latency {
            Some(stats) if stats.sample_count > 0 => {
                stats.timeout_rate() <= policy.max_timeout_rate
                    && stats.failure_rate() <= policy.max_failure_rate
            }
            _ => true,
        }
    }
}

/// Exclusion thresholds for endpoint health, as rates in `[0.0, 1.0]`.
/// Endpoints are excluded outright, not merely down-ranked — safety always
/// overrides speed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HealthPolicy {
    pub max_timeout_rate: f64,
    pub max_failure_rate: f64,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            max_timeout_rate: 0.5,
            max_failure_rate: 0.5,
        }
    }
}

/// Take up to `config.sample_count` bounded, sequential samples of a
/// cheap, safe read call (`eth_blockNumber`) against `client`. Callers must
/// only invoke this for a client whose role permits reads.
pub async fn benchmark_read_latency(client: &RpcClient, config: &BenchmarkConfig) -> LatencyStats {
    let mut samples = Vec::with_capacity(config.sample_count as usize);
    for i in 0..config.sample_count {
        let started = Instant::now();
        let outcome = match client.block_number().await {
            Ok(_) => SampleOutcome::Ok(duration_ms(started.elapsed())),
            Err(RpcError::Transport(TransportError::Timeout(_))) => SampleOutcome::Timeout,
            Err(_) => SampleOutcome::Error,
        };
        samples.push(outcome);
        if i + 1 < config.sample_count && config.sample_delay > Duration::ZERO {
            tokio::time::sleep(config.sample_delay).await;
        }
    }
    LatencyStats::from_samples(&samples)
}

fn duration_ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

/// Deterministically select the single best read-capable, chain-verified,
/// healthy endpoint by lowest median read latency. Ties break on label so
/// selection never depends on iteration/hash order. Returns `None` (fail
/// closed) if nothing eligible exists.
pub fn select_read_endpoint<'a>(
    candidates: &[(&'a RpcClient, &EndpointBenchmark)],
    policy: &HealthPolicy,
) -> Option<&'a RpcClient> {
    candidates
        .iter()
        .filter(|(_, bench)| bench.is_healthy_for_read(policy))
        .filter_map(|(client, bench)| {
            bench
                .read_latency
                .and_then(|s| s.median_ms)
                .map(|m| (*client, m))
        })
        .min_by(|(a_client, a_ms), (b_client, b_ms)| {
            a_ms.cmp(b_ms).then_with(|| {
                a_client
                    .label()
                    .unwrap_or("")
                    .cmp(b_client.label().unwrap_or(""))
            })
        })
        .map(|(client, _)| client)
}

/// Every send-capable candidate that clears the health policy, in a
/// deterministic (label-sorted) order. Never reduces to "just the fastest
/// one" — Phase 3's send-endpoint policy is about excluding clearly-dead
/// endpoints, not ranking by speed; independent propagation paths matter
/// more than shaving a few milliseconds off one of several concurrent
/// broadcasts.
pub fn select_send_endpoints<'a>(
    candidates: &[(&'a RpcClient, &EndpointBenchmark)],
    policy: &HealthPolicy,
) -> Vec<&'a RpcClient> {
    let mut selected: Vec<&RpcClient> = candidates
        .iter()
        .filter(|(_, bench)| bench.is_healthy_for_send(policy))
        .map(|(client, _)| *client)
        .collect();
    selected.sort_by_key(|c| c.label().unwrap_or("").to_string());
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::endpoint::{EndpointRole, EndpointVerification};
    use crate::chain::mock::MockTransport;
    use crate::chain::rpc::RpcClient;
    use serde_json::json;

    #[test]
    fn latency_stats_basic_aggregates() {
        let samples = [
            SampleOutcome::Ok(10),
            SampleOutcome::Ok(20),
            SampleOutcome::Ok(30),
            SampleOutcome::Ok(40),
            SampleOutcome::Ok(50),
        ];
        let stats = LatencyStats::from_samples(&samples);
        assert_eq!(stats.sample_count, 5);
        assert_eq!(stats.successes, 5);
        assert_eq!(stats.min_ms, Some(10));
        assert_eq!(stats.max_ms, Some(50));
        assert_eq!(stats.mean_ms, Some(30));
        assert_eq!(stats.median_ms, Some(30));
    }

    #[test]
    fn latency_stats_p90_p95_on_ten_samples() {
        let samples: Vec<SampleOutcome> = (1..=10).map(|n| SampleOutcome::Ok(n * 10)).collect();
        let stats = LatencyStats::from_samples(&samples);
        // Nearest-rank on a 0-indexed 10-element sorted vec [10..100]:
        // p90 -> index round(0.9*9)=8 -> value 90; p95 -> round(0.95*9)=9 -> 100.
        assert_eq!(stats.p90_ms, Some(90));
        assert_eq!(stats.p95_ms, Some(100));
    }

    #[test]
    fn latency_stats_counts_timeouts_and_failures_separately() {
        let samples = [
            SampleOutcome::Ok(5),
            SampleOutcome::Timeout,
            SampleOutcome::Timeout,
            SampleOutcome::Error,
        ];
        let stats = LatencyStats::from_samples(&samples);
        assert_eq!(stats.sample_count, 4);
        assert_eq!(stats.successes, 1);
        assert_eq!(stats.timeouts, 2);
        assert_eq!(stats.failures, 1);
        assert!((stats.timeout_rate() - 0.5).abs() < f64::EPSILON);
        assert!((stats.failure_rate() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_stats_all_failed_has_no_latency_values() {
        let samples = [SampleOutcome::Timeout, SampleOutcome::Error];
        let stats = LatencyStats::from_samples(&samples);
        assert_eq!(stats.min_ms, None);
        assert_eq!(stats.median_ms, None);
        assert_eq!(stats.mean_ms, None);
    }

    async fn read_client(label: &str) -> RpcClient {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .build();
        RpcClient::connect(
            Box::new(transport),
            1,
            EndpointRole::ReadOnly,
            Some(label.to_string()),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn benchmark_read_latency_produces_requested_sample_count() {
        let client = read_client("a").await;
        let config = BenchmarkConfig {
            sample_count: 3,
            sample_delay: Duration::ZERO,
        };
        let stats = benchmark_read_latency(&client, &config).await;
        assert_eq!(stats.sample_count, 3);
        assert_eq!(stats.successes, 3);
        assert_eq!(stats.failures, 0);
    }

    #[tokio::test]
    async fn benchmark_read_latency_classifies_timeout_samples() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .delay("eth_blockNumber", Duration::from_millis(50))
            .build()
            .with_call_timeout(Duration::from_millis(1));
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let config = BenchmarkConfig {
            sample_count: 2,
            sample_delay: Duration::ZERO,
        };
        let stats = benchmark_read_latency(&client, &config).await;
        assert_eq!(stats.timeouts, 2);
        assert_eq!(stats.successes, 0);
    }

    #[tokio::test]
    async fn benchmark_never_calls_send_raw_transaction() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_blockNumber", json!("0x1"))
            .build();
        let capture = transport.capture_handle();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let config = BenchmarkConfig {
            sample_count: 3,
            sample_delay: Duration::ZERO,
        };
        benchmark_read_latency(&client, &config).await;
        assert!(capture.calls_for("eth_sendRawTransaction").is_empty());
        assert!(capture.prebuilt_bodies().is_empty());
    }

    fn bench_with_median(label: &str, role: EndpointRole, median_ms: u64) -> EndpointBenchmark {
        EndpointBenchmark {
            label: Some(label.to_string()),
            role,
            verification: EndpointVerification::VerifiedReadWrite,
            connection_latency_ms: None,
            read_latency: Some(LatencyStats {
                sample_count: 5,
                successes: 5,
                failures: 0,
                timeouts: 0,
                min_ms: Some(median_ms),
                max_ms: Some(median_ms),
                mean_ms: Some(median_ms),
                median_ms: Some(median_ms),
                p90_ms: Some(median_ms),
                p95_ms: Some(median_ms),
            }),
            broadcast_latency: if role.can_send() {
                BroadcastLatency::UnknownUntilRealAttempt
            } else {
                BroadcastLatency::NotApplicable
            },
        }
    }

    #[tokio::test]
    async fn select_read_endpoint_prefers_lower_median() {
        let fast = read_client("fast").await;
        let slow = read_client("slow").await;
        let fast_bench = bench_with_median("fast", EndpointRole::ReadOnly, 10);
        let slow_bench = bench_with_median("slow", EndpointRole::ReadOnly, 40);
        let candidates = [(&fast, &fast_bench), (&slow, &slow_bench)];
        let selected = select_read_endpoint(&candidates, &HealthPolicy::default()).unwrap();
        assert_eq!(selected.label(), Some("fast"));
    }

    #[tokio::test]
    async fn select_read_endpoint_deterministic_tie_break_by_label() {
        let b = read_client("b").await;
        let a = read_client("a").await;
        let bench_b = bench_with_median("b", EndpointRole::ReadOnly, 10);
        let bench_a = bench_with_median("a", EndpointRole::ReadOnly, 10);
        let candidates = [(&b, &bench_b), (&a, &bench_a)];
        let selected = select_read_endpoint(&candidates, &HealthPolicy::default()).unwrap();
        assert_eq!(
            selected.label(),
            Some("a"),
            "equal scores must break deterministically"
        );
    }

    #[tokio::test]
    async fn select_read_endpoint_excludes_non_read_role_even_with_fast_synthetic_latency() {
        // A SendOnly client can never actually carry real read_latency data
        // (benchmark_read_latency is only ever called for read-capable
        // clients), but this proves the exclusion is enforced by role, not
        // merely by "we never measured it" — even adversarial/synthetic
        // data attached to a send-only role must not win a read selection.
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let sendonly_client = RpcClient::connect(
            Box::new(transport),
            1,
            EndpointRole::SendOnly,
            Some("fast-but-sendonly".into()),
        )
        .await
        .unwrap();
        let synthetic_fast_bench =
            bench_with_median("fast-but-sendonly", EndpointRole::SendOnly, 1);

        let slow_readonly = read_client("slow-but-readonly").await;
        let slow_bench = bench_with_median("slow-but-readonly", EndpointRole::ReadOnly, 999);

        let candidates = [
            (&sendonly_client, &synthetic_fast_bench),
            (&slow_readonly, &slow_bench),
        ];
        let selected = select_read_endpoint(&candidates, &HealthPolicy::default()).unwrap();
        assert_eq!(
            selected.label(),
            Some("slow-but-readonly"),
            "a send-only role must lose to a verified read-capable one regardless of latency"
        );
    }

    #[tokio::test]
    async fn select_read_endpoint_excludes_unhealthy_high_timeout_candidate() {
        let healthy = read_client("healthy").await;
        let unhealthy = read_client("unhealthy").await;
        let healthy_bench = bench_with_median("healthy", EndpointRole::ReadOnly, 50);
        let mut unhealthy_bench = bench_with_median("unhealthy", EndpointRole::ReadOnly, 5);
        unhealthy_bench.read_latency = Some(LatencyStats {
            sample_count: 4,
            successes: 1,
            failures: 0,
            timeouts: 3,
            min_ms: Some(5),
            max_ms: Some(5),
            mean_ms: Some(5),
            median_ms: Some(5),
            p90_ms: Some(5),
            p95_ms: Some(5),
        });
        let candidates = [(&healthy, &healthy_bench), (&unhealthy, &unhealthy_bench)];
        let selected = select_read_endpoint(&candidates, &HealthPolicy::default()).unwrap();
        assert_eq!(
            selected.label(),
            Some("healthy"),
            "75% timeout rate must be excluded"
        );
    }

    #[tokio::test]
    async fn select_read_endpoint_none_when_nothing_eligible() {
        let sendonly_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let sendonly = RpcClient::connect(
            Box::new(sendonly_transport),
            1,
            EndpointRole::SendOnly,
            None,
        )
        .await
        .unwrap();
        let bench = EndpointBenchmark::initial(&sendonly);
        let candidates = [(&sendonly, &bench)];
        assert!(select_read_endpoint(&candidates, &HealthPolicy::default()).is_none());
    }

    #[tokio::test]
    async fn select_send_endpoints_includes_configured_send_only_without_read_data() {
        let transport = MockTransport::builder().build();
        let configured_send_only = RpcClient::connect(
            Box::new(transport),
            1,
            EndpointRole::Sequencer,
            Some("seq".into()),
        )
        .await
        .unwrap();
        let bench = EndpointBenchmark::initial(&configured_send_only);
        let candidates = [(&configured_send_only, &bench)];
        let selected = select_send_endpoints(&candidates, &HealthPolicy::default());
        assert_eq!(selected.len(), 1);
    }

    #[tokio::test]
    async fn select_send_endpoints_excludes_read_only_role() {
        let client = read_client("ro").await;
        let bench = bench_with_median("ro", EndpointRole::ReadOnly, 10);
        let candidates = [(&client, &bench)];
        assert!(select_send_endpoints(&candidates, &HealthPolicy::default()).is_empty());
    }

    #[tokio::test]
    async fn select_send_endpoints_excludes_dead_read_write_node() {
        let dead = read_client("dead-rw").await;
        let mut dead_bench = bench_with_median("dead-rw", EndpointRole::ReadWrite, 10);
        dead_bench.read_latency = Some(LatencyStats {
            sample_count: 4,
            successes: 0,
            failures: 4,
            timeouts: 0,
            min_ms: None,
            max_ms: None,
            mean_ms: None,
            median_ms: None,
            p90_ms: None,
            p95_ms: None,
        });
        let candidates = [(&dead, &dead_bench)];
        assert!(
            select_send_endpoints(&candidates, &HealthPolicy::default()).is_empty(),
            "a read-write node with a 100% failure rate must be excluded from sending too"
        );
    }

    #[tokio::test]
    async fn select_send_endpoints_deterministic_ordering() {
        let z = read_client("z").await;
        let a = read_client("a").await;
        let bench_z = bench_with_median("z", EndpointRole::ReadWrite, 10);
        let bench_a = bench_with_median("a", EndpointRole::ReadWrite, 10);
        let candidates = [(&z, &bench_z), (&a, &bench_a)];
        let selected = select_send_endpoints(&candidates, &HealthPolicy::default());
        assert_eq!(selected[0].label(), Some("a"));
        assert_eq!(selected[1].label(), Some("z"));
    }
}
