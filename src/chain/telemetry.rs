//! Small, bounded, in-memory, advisory-only telemetry gathered
//! opportunistically during `watch`'s existing pre-T0 polling
//! (`execution::watch::wait_for_stage`'s repeated `StageProbe::probe()`
//! calls -- see `cli::commands::watch::TelemetryProbe`, which wraps a
//! probe to record its own latency/outcome here without changing
//! `wait_for_stage` itself at all).
//!
//! Deliberately minimal, per this pass's explicit scope:
//! - in-memory only, scoped to exactly one watch session (constructed
//!   fresh per `run_single_target` call, dropped when it returns -- no
//!   background task, no persistence, nothing to shut down separately).
//! - every collection is bounded: each endpoint's latency ring buffer is
//!   capped at [`MAX_SAMPLES`]; there is no per-session cap on distinct
//!   endpoint labels because that set is itself bounded (one label per
//!   configured RPC endpoint/probe, never operator- or network-supplied).
//! - recording is synchronous and piggybacks on I/O `wait_for_stage`
//!   already performs -- this module never issues its own RPC/HTTP call,
//!   never spawns a task, and a recording failure (a poisoned mutex) is
//!   handled by simply not recording, never by panicking or blocking the
//!   probe it decorates.
//! - purely advisory: nothing here is ever consulted by a signing or
//!   spend-authorization decision. See module docs on
//!   [`TelemetryStore`] for the mandatory-fresh-check invariant this
//!   must never weaken.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Bounded ring buffer size -- old samples are dropped, never grown
/// without limit.
const MAX_SAMPLES: usize = 32;

/// What's been observed about one endpoint/probe across a watch
/// session's repeated polling.
#[derive(Debug, Clone, Default)]
pub struct EndpointTelemetry {
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    latency_samples_ms: VecDeque<u64>,
    pub consecutive_failures: u32,
}

impl EndpointTelemetry {
    fn record_success(&mut self, latency_ms: u64, now: Instant) {
        self.last_success = Some(now);
        self.consecutive_failures = 0;
        if self.latency_samples_ms.len() == MAX_SAMPLES {
            self.latency_samples_ms.pop_front();
        }
        self.latency_samples_ms.push_back(latency_ms);
    }

    fn record_failure(&mut self, now: Instant) {
        self.last_failure = Some(now);
        self.consecutive_failures += 1;
    }

    pub fn sample_count(&self) -> usize {
        self.latency_samples_ms.len()
    }

    /// `None` when there are zero successful samples yet -- never a
    /// fabricated "no data" placeholder value like `0`.
    pub fn median_ms(&self) -> Option<u64> {
        percentile(&self.latency_samples_ms, 50.0)
    }

    pub fn p90_ms(&self) -> Option<u64> {
        percentile(&self.latency_samples_ms, 90.0)
    }

    pub fn p95_ms(&self) -> Option<u64> {
        percentile(&self.latency_samples_ms, 95.0)
    }
}

fn percentile(samples: &VecDeque<u64>, pct: f64) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted: Vec<u64> = samples.iter().copied().collect();
    sorted.sort_unstable();
    let rank = ((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted.get(rank.min(sorted.len() - 1)).copied()
}

/// Best-effort, opportunistically-populated network fee/block
/// observations. Not currently populated by any caller this pass (see
/// the final report for why) -- present so the shape exists and a
/// future caller with a genuine, low-risk source for these values (a
/// probe that already reads them, without adding a new RPC call to the
/// wait loop purely to feed this struct) can populate it without another
/// type change.
#[derive(Debug, Clone, Default)]
pub struct NetworkTelemetry {
    pub latest_base_fee_wei: Option<u128>,
    pub latest_priority_fee_wei: Option<u128>,
    pub latest_block_unix_timestamp: Option<i64>,
    pub freshness: Option<Instant>,
}

/// A bounded, in-memory, advisory-only telemetry store scoped to exactly
/// one watch session. **Never consulted by any signing or spend
/// -authorization decision** -- every mandatory fresh check
/// (stage/authorization validity, allocation, supply, nonce, fee,
/// balance, spend caps, simulation) remains exactly what it was before
/// this module existed, sourced fresh at prepare/sign time, never from
/// here. This exists purely to give an operator visibility into observed
/// endpoint health/latency during a long wait, and as a foundation a
/// future pass could use for *performance* decisions (e.g. endpoint
/// ordering) -- never correctness or authorization ones.
#[derive(Debug, Default)]
pub struct TelemetryStore {
    endpoints: HashMap<String, EndpointTelemetry>,
    pub network: NetworkTelemetry,
}

impl TelemetryStore {
    pub fn record_probe_success(&mut self, label: &str, latency_ms: u64) {
        self.endpoints
            .entry(label.to_string())
            .or_default()
            .record_success(latency_ms, Instant::now());
    }

    pub fn record_probe_failure(&mut self, label: &str) {
        self.endpoints
            .entry(label.to_string())
            .or_default()
            .record_failure(Instant::now());
    }

    pub fn endpoint(&self, label: &str) -> Option<&EndpointTelemetry> {
        self.endpoints.get(label)
    }

    /// One human-readable line per observed endpoint, for an operator
    /// -facing advisory summary -- never parsed back by any code.
    pub fn summary_lines(&self) -> Vec<String> {
        let mut labels: Vec<&String> = self.endpoints.keys().collect();
        labels.sort();
        labels
            .into_iter()
            .map(|label| {
                let t = &self.endpoints[label];
                format!(
                    "{label}: {} sample(s), median {}, p90 {}, p95 {}, {} consecutive failure(s)",
                    t.sample_count(),
                    t.median_ms()
                        .map(|v| format!("{v}ms"))
                        .unwrap_or_else(|| "n/a".into()),
                    t.p90_ms()
                        .map(|v| format!("{v}ms"))
                        .unwrap_or_else(|| "n/a".into()),
                    t.p95_ms()
                        .map(|v| format!("{v}ms"))
                        .unwrap_or_else(|| "n/a".into()),
                    t.consecutive_failures,
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_is_bounded_and_drops_oldest_samples() {
        let mut store = TelemetryStore::default();
        for i in 0..(MAX_SAMPLES + 10) {
            store.record_probe_success("node-0", i as u64);
        }
        let t = store.endpoint("node-0").unwrap();
        assert_eq!(t.sample_count(), MAX_SAMPLES);
    }

    #[test]
    fn success_resets_consecutive_failure_count() {
        let mut store = TelemetryStore::default();
        store.record_probe_failure("node-0");
        store.record_probe_failure("node-0");
        assert_eq!(store.endpoint("node-0").unwrap().consecutive_failures, 2);
        store.record_probe_success("node-0", 10);
        assert_eq!(store.endpoint("node-0").unwrap().consecutive_failures, 0);
    }

    #[test]
    fn median_and_percentiles_are_none_with_no_samples() {
        let mut store = TelemetryStore::default();
        store.record_probe_failure("node-0");
        let t = store.endpoint("node-0").unwrap();
        assert_eq!(t.median_ms(), None);
        assert_eq!(t.p90_ms(), None);
        assert_eq!(t.p95_ms(), None);
    }

    #[test]
    fn median_is_computed_correctly_for_a_known_sample_set() {
        let mut store = TelemetryStore::default();
        for ms in [10, 20, 30, 40, 50] {
            store.record_probe_success("node-0", ms);
        }
        let t = store.endpoint("node-0").unwrap();
        assert_eq!(t.median_ms(), Some(30));
    }

    #[test]
    fn distinct_endpoints_are_tracked_independently() {
        let mut store = TelemetryStore::default();
        store.record_probe_success("node-0", 10);
        store.record_probe_failure("node-1");
        assert_eq!(store.endpoint("node-0").unwrap().sample_count(), 1);
        assert_eq!(store.endpoint("node-1").unwrap().consecutive_failures, 1);
        assert_eq!(store.endpoint("node-1").unwrap().sample_count(), 0);
    }

    #[test]
    fn unknown_endpoint_returns_none_not_a_default_placeholder() {
        let store = TelemetryStore::default();
        assert!(store.endpoint("never-seen").is_none());
    }

    #[test]
    fn summary_lines_are_sorted_and_include_every_recorded_endpoint() {
        let mut store = TelemetryStore::default();
        store.record_probe_success("b-node", 5);
        store.record_probe_success("a-node", 5);
        let lines = store.summary_lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("a-node"));
        assert!(lines[1].starts_with("b-node"));
    }
}
