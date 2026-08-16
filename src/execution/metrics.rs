//! Latency metrics for the live mint pipeline.
//!
//! Every field is populated as the pipeline progresses and printed once,
//! after dispatch — never inside the T=0 hot path, which must stay free of
//! anything beyond broadcasting precomputed bytes.

use std::time::Instant;

/// A single named timer. `elapsed_ms` may be called any number of times;
/// it does not stop the clock.
#[derive(Debug, Clone, Copy)]
pub struct Stopwatch(Instant);

impl Stopwatch {
    pub fn start() -> Self {
        Self(Instant::now())
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.0.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
}

impl Default for Stopwatch {
    fn default() -> Self {
        Self::start()
    }
}

/// Buffered latency measurements for one live mint attempt, in the order
/// the pipeline produces them.
#[derive(Debug, Clone, Default)]
pub struct LatencyMetrics {
    pub rpc_connect_ms: Option<u64>,
    pub rpc_chainid_ms: Option<u64>,
    /// Time spent establishing/pre-warming every configured endpoint's
    /// connection (Phase 3), before any benchmarking or state reads begin.
    pub prewarm_ms: Option<u64>,
    /// Time spent taking repeated read-latency samples across every
    /// read-capable endpoint (Phase 3).
    pub benchmark_ms: Option<u64>,
    /// Time spent deterministically selecting the read endpoint and the
    /// send-endpoint set from benchmark data (Phase 3). Expected to be
    /// negligible; measured anyway for auditability.
    pub endpoint_selection_ms: Option<u64>,
    pub metadata_ms: Option<u64>,
    pub nonce_ms: Option<u64>,
    pub fee_ms: Option<u64>,
    pub simulation_ms: Option<u64>,
    pub sign_ms: Option<u64>,
    pub serialize_ms: Option<u64>,
    /// Time spent building the prebuilt broadcast payload — hex-encoding
    /// the raw signed transaction and serializing the complete
    /// `eth_sendRawTransaction` JSON-RPC request body — measured once,
    /// before T=0. Distinct from `dispatch_ms`, which measures only actual
    /// network fan-out against the already-built payload.
    pub broadcast_prepare_ms: Option<u64>,
    pub scheduler_error_ms: Option<i64>,
    pub dispatch_ms: Option<u64>,
    pub rpc_accept_ms: Option<u64>,
    pub receipt_inclusion_ms: Option<u64>,
}

impl LatencyMetrics {
    /// Render as a compact, human-readable block. Callers print this once,
    /// after the hot path — never during it.
    pub fn render(&self) -> String {
        let field = |name: &str, value: Option<u64>| match value {
            Some(v) => format!("  {name:<24} {v} ms"),
            None => format!("  {name:<24} n/a"),
        };
        let mut lines = vec![
            field("rpc_connect_ms", self.rpc_connect_ms),
            field("rpc_chainid_ms", self.rpc_chainid_ms),
            field("prewarm_ms", self.prewarm_ms),
            field("benchmark_ms", self.benchmark_ms),
            field("endpoint_selection_ms", self.endpoint_selection_ms),
            field("metadata_ms", self.metadata_ms),
            field("nonce_ms", self.nonce_ms),
            field("fee_ms", self.fee_ms),
            field("simulation_ms", self.simulation_ms),
            field("sign_ms", self.sign_ms),
            field("serialize_ms", self.serialize_ms),
            field("broadcast_prepare_ms", self.broadcast_prepare_ms),
        ];
        lines.push(match self.scheduler_error_ms {
            Some(v) => format!("  {:<24} {v} ms", "scheduler_error_ms"),
            None => format!("  {:<24} n/a", "scheduler_error_ms"),
        });
        lines.push(field("dispatch_ms", self.dispatch_ms));
        lines.push(field("rpc_accept_ms", self.rpc_accept_ms));
        lines.push(field("receipt_inclusion_ms", self.receipt_inclusion_ms));
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn stopwatch_elapsed_ms_increases_monotonically() {
        let sw = Stopwatch::start();
        sleep(Duration::from_millis(5));
        let first = sw.elapsed_ms();
        sleep(Duration::from_millis(5));
        let second = sw.elapsed_ms();
        assert!(second >= first);
    }

    #[test]
    fn render_shows_na_for_unset_fields() {
        let metrics = LatencyMetrics::default();
        let rendered = metrics.render();
        assert!(rendered.contains("n/a"));
        assert!(rendered.contains("rpc_connect_ms"));
        assert!(rendered.contains("receipt_inclusion_ms"));
    }

    #[test]
    fn render_shows_set_values() {
        let metrics = LatencyMetrics {
            sign_ms: Some(12),
            ..Default::default()
        };
        let rendered = metrics.render();
        assert!(rendered.contains("sign_ms"));
        assert!(rendered.contains("12 ms"));
    }
}
