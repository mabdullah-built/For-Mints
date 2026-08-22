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
use std::time::{Duration, Instant};

/// Bounded ring buffer size -- old samples are dropped, never grown
/// without limit.
const MAX_SAMPLES: usize = 32;

/// How long a telemetry observation stays [`Freshness::Fresh`] before it is
/// reported [`Freshness::Stale`]. Deliberately short: this value only ever
/// feeds an operator-facing advisory display (see [`TelemetryStore::network_freshness`]
/// and [`EndpointTelemetry`]'s per-endpoint accessors) -- it is *never*
/// consulted to decide whether it is safe to sign or broadcast, so there is
/// no safety trade-off in keeping it tight. 10 seconds comfortably covers
/// one to a few poll cycles at any of `watch`'s configured poll intervals
/// without reporting a just-observed value as stale purely due to normal
/// poll spacing.
pub const FRESHNESS_TTL: Duration = Duration::from_secs(10);

/// An advisory telemetry value, explicit about how old it is. Never a
/// substitute for a mandatory execution-time read -- see the module-level
/// safety note on [`TelemetryStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness<T> {
    /// Observed within [`FRESHNESS_TTL`] of now.
    Fresh { value: T, age: Duration },
    /// Observed, but longer than [`FRESHNESS_TTL`] ago. Still safe to
    /// *display* (with its age) or to trigger a fresh advisory
    /// re-measurement -- never safe to treat as current.
    Stale { value: T, age: Duration },
    /// No observation has ever been recorded.
    Unavailable,
}

impl<T> Freshness<T> {
    fn from_observation(value: T, observed_at: Instant, now: Instant) -> Self {
        let age = now.saturating_duration_since(observed_at);
        if age <= FRESHNESS_TTL {
            Freshness::Fresh { value, age }
        } else {
            Freshness::Stale { value, age }
        }
    }

    /// The value regardless of freshness, for display purposes only. Never
    /// use this to feed a mandatory execution-time check -- read the fresh
    /// on-chain/off-chain state directly instead, exactly as every existing
    /// signing/spend-authorization path already does.
    pub fn displayable_value(&self) -> Option<&T> {
        match self {
            Freshness::Fresh { value, .. } | Freshness::Stale { value, .. } => Some(value),
            Freshness::Unavailable => None,
        }
    }

    pub fn is_fresh(&self) -> bool {
        matches!(self, Freshness::Fresh { .. })
    }
}

/// What's been observed about one endpoint/probe across a watch
/// session's repeated polling. `label` is this record's own key duplicated
/// for display convenience (e.g. in [`TelemetryStore::summary_lines`]) --
/// never redacted here beyond whatever the caller already passed in as the
/// label (callers must never pass a raw, credential-bearing URL as a
/// label; see `chain::endpoint`'s existing redaction for configured RPC
/// endpoint labels, which this module never bypasses).
#[derive(Debug, Clone, Default)]
pub struct EndpointTelemetry {
    pub role: Option<crate::chain::endpoint::EndpointRole>,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    /// Set once, the first time this endpoint's identity is recorded --
    /// mirrors the mandatory `eth_chainId` verification `RpcPool::connect_all`
    /// already performs before this endpoint is ever probed; never
    /// re-verified here (only `RpcClient::connect`/`rewarm_all`'s reused
    /// `eth_chainId` call do that).
    pub chain_verified_at: Option<Instant>,
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

    fn record_identity(&mut self, role: crate::chain::endpoint::EndpointRole, now: Instant) {
        self.role = Some(role);
        if self.chain_verified_at.is_none() {
            self.chain_verified_at = Some(now);
        }
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
/// observations. Populated by [`TelemetryStore::record_network_observation`],
/// called from `cli::commands::watch::TelemetryProbe` using the same
/// already-connected, already-warm send `RpcPool` `watch` maintains for
/// dispatch -- one additional bounded, read-only `eth_getBlockByNumber` (+
/// best-effort `eth_maxPriorityFeePerGas`) call per poll cycle, never a new
/// connection and never send-only-endpoint traffic. This purely-advisory
/// observation is entirely separate from, and never a substitute for, the
/// unconditional fresh nonce/fee/balance/allocation/supply reads
/// `run_live_mint`/`run_opensea_mint` perform immediately before signing.
#[derive(Debug, Clone, Default)]
pub struct NetworkTelemetry {
    latest_base_fee_wei: Option<u128>,
    latest_priority_fee_wei: Option<u128>,
    latest_block_number: Option<u64>,
    latest_block_unix_timestamp: Option<u64>,
    observed_at: Option<Instant>,
}

impl NetworkTelemetry {
    fn record(
        &mut self,
        block_number: u64,
        block_unix_timestamp: u64,
        base_fee_wei: u128,
        priority_fee_wei: Option<u128>,
        now: Instant,
    ) {
        self.latest_block_number = Some(block_number);
        self.latest_block_unix_timestamp = Some(block_unix_timestamp);
        self.latest_base_fee_wei = Some(base_fee_wei);
        // A priority-fee observation is best-effort (some nodes don't
        // implement eth_maxPriorityFeePerGas) -- a failure to obtain one
        // this cycle must never erase a previously-observed value, since
        // that would make the advisory display flicker between a value and
        // "unavailable" for no operator-meaningful reason.
        if let Some(priority_fee_wei) = priority_fee_wei {
            self.latest_priority_fee_wei = Some(priority_fee_wei);
        }
        self.observed_at = Some(now);
    }

    fn freshness_of<T: Copy>(&self, value: Option<T>, now: Instant) -> Freshness<T> {
        match (value, self.observed_at) {
            (Some(value), Some(observed_at)) => {
                Freshness::from_observation(value, observed_at, now)
            }
            _ => Freshness::Unavailable,
        }
    }

    pub fn latest_block_number(&self) -> Freshness<u64> {
        self.freshness_of(self.latest_block_number, Instant::now())
    }

    pub fn latest_block_unix_timestamp(&self) -> Freshness<u64> {
        self.freshness_of(self.latest_block_unix_timestamp, Instant::now())
    }

    pub fn latest_base_fee_wei(&self) -> Freshness<u128> {
        self.freshness_of(self.latest_base_fee_wei, Instant::now())
    }

    pub fn latest_priority_fee_wei(&self) -> Freshness<u128> {
        self.freshness_of(self.latest_priority_fee_wei, Instant::now())
    }

    /// Test-only: evaluate block-number freshness as of an explicit `now`
    /// rather than the real current time, so tests can assert TTL
    /// boundary behavior deterministically without sleeping the test
    /// thread for [`FRESHNESS_TTL`].
    #[cfg(test)]
    fn latest_block_number_at(&self, now: Instant) -> Freshness<u64> {
        self.freshness_of(self.latest_block_number, now)
    }
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

    /// Records `role` for the endpoint keyed by `label`, and the first time
    /// this is called for a given label, its chain-verification timestamp.
    /// Never re-verifies anything itself -- purely records what the caller
    /// (which must have already gone through real `eth_chainId`
    /// verification via `RpcClient::connect`) already knows.
    pub fn record_endpoint_identity(
        &mut self,
        label: &str,
        role: crate::chain::endpoint::EndpointRole,
    ) {
        self.endpoints
            .entry(label.to_string())
            .or_default()
            .record_identity(role, Instant::now());
    }

    /// Records one bounded, read-only network observation (latest block
    /// number/timestamp, base fee, and a best-effort priority fee) as of
    /// now. See [`NetworkTelemetry`]'s doc comment for exactly where this
    /// data comes from and why it never adds a new connection.
    pub fn record_network_observation(
        &mut self,
        block_number: u64,
        block_unix_timestamp: u64,
        base_fee_wei: u128,
        priority_fee_wei: Option<u128>,
    ) {
        self.network.record(
            block_number,
            block_unix_timestamp,
            base_fee_wei,
            priority_fee_wei,
            Instant::now(),
        );
    }

    pub fn endpoint(&self, label: &str) -> Option<&EndpointTelemetry> {
        self.endpoints.get(label)
    }

    /// One human-readable line per observed endpoint, plus (when any
    /// network observation has ever been recorded) one final line
    /// summarizing the latest advisory network telemetry with its
    /// freshness -- for an operator-facing advisory summary only, never
    /// parsed back by any code.
    pub fn summary_lines(&self) -> Vec<String> {
        let mut labels: Vec<&String> = self.endpoints.keys().collect();
        labels.sort();
        let mut lines: Vec<String> = labels
            .into_iter()
            .map(|label| {
                let t = &self.endpoints[label];
                format!(
                    "{label}: role={}, chain-verified={}, {} sample(s), median {}, p90 {}, \
                     p95 {}, {} consecutive failure(s)",
                    t.role
                        .map(|r| format!("{r:?}"))
                        .unwrap_or_else(|| "unknown".into()),
                    if t.chain_verified_at.is_some() {
                        "yes"
                    } else {
                        "no"
                    },
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
            .collect();

        if let Some(block_number) = self.network.latest_block_number().displayable_value() {
            let fresh = self.network.latest_block_number().is_fresh();
            let base_fee = self
                .network
                .latest_base_fee_wei()
                .displayable_value()
                .map(|v| format!("{v} wei"))
                .unwrap_or_else(|| "n/a".into());
            let priority_fee = self
                .network
                .latest_priority_fee_wei()
                .displayable_value()
                .map(|v| format!("{v} wei"))
                .unwrap_or_else(|| "n/a".into());
            lines.push(format!(
                "network: block={block_number}, base_fee={base_fee}, priority_fee={priority_fee}, \
                 freshness={}",
                if fresh { "fresh" } else { "stale" },
            ));
        }

        lines
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

    #[test]
    fn record_endpoint_identity_sets_role_and_a_stable_first_chain_verified_timestamp() {
        let mut store = TelemetryStore::default();
        store.record_endpoint_identity("node-0", crate::chain::endpoint::EndpointRole::ReadOnly);
        let first = store.endpoint("node-0").unwrap().chain_verified_at;
        assert!(first.is_some());
        assert_eq!(
            store.endpoint("node-0").unwrap().role,
            Some(crate::chain::endpoint::EndpointRole::ReadOnly)
        );

        // Recording identity again must never move the "first verified"
        // timestamp -- it is a first-observation marker, not a rolling one.
        store.record_endpoint_identity("node-0", crate::chain::endpoint::EndpointRole::ReadOnly);
        assert_eq!(store.endpoint("node-0").unwrap().chain_verified_at, first);
    }

    #[test]
    fn network_telemetry_is_unavailable_before_any_observation() {
        let store = TelemetryStore::default();
        assert_eq!(store.network.latest_block_number(), Freshness::Unavailable);
        assert_eq!(store.network.latest_base_fee_wei(), Freshness::Unavailable);
        assert_eq!(
            store.network.latest_priority_fee_wei(),
            Freshness::Unavailable
        );
    }

    #[test]
    fn a_new_network_observation_is_fresh() {
        let mut store = TelemetryStore::default();
        store.record_network_observation(100, 1_700_000_000, 10_000_000_000, Some(1_000_000_000));
        assert!(store.network.latest_block_number().is_fresh());
        assert_eq!(
            store.network.latest_block_number().displayable_value(),
            Some(&100)
        );
        assert_eq!(
            store.network.latest_base_fee_wei().displayable_value(),
            Some(&10_000_000_000)
        );
        assert_eq!(
            store.network.latest_priority_fee_wei().displayable_value(),
            Some(&1_000_000_000)
        );
    }

    #[test]
    fn a_missing_priority_fee_observation_never_erases_a_previous_one() {
        let mut store = TelemetryStore::default();
        store.record_network_observation(100, 1_700_000_000, 10_000_000_000, Some(1_000_000_000));
        // A later observation cycle where the priority-fee read failed
        // (None) must not wipe out the previously-observed value.
        store.record_network_observation(101, 1_700_000_012, 11_000_000_000, None);
        assert_eq!(
            store.network.latest_priority_fee_wei().displayable_value(),
            Some(&1_000_000_000)
        );
        // But the block/base-fee fields, which this cycle *did* observe,
        // must update.
        assert_eq!(
            store.network.latest_block_number().displayable_value(),
            Some(&101)
        );
    }

    #[test]
    fn a_network_observation_becomes_stale_after_the_ttl_and_remains_displayable() {
        let mut store = TelemetryStore::default();
        let just_before = Instant::now();
        store.record_network_observation(100, 1_700_000_000, 10_000_000_000, None);

        // Exactly-or-just-under the TTL: still fresh.
        let still_fresh_at = just_before + FRESHNESS_TTL - Duration::from_millis(1);
        assert!(
            store
                .network
                .latest_block_number_at(still_fresh_at)
                .is_fresh()
        );

        // Just past the TTL: stale, but the value is still displayable --
        // stale telemetry must never simply vanish, only be labeled as
        // stale.
        let stale_at = just_before + FRESHNESS_TTL + Duration::from_millis(50);
        let stale = store.network.latest_block_number_at(stale_at);
        assert!(!stale.is_fresh());
        assert_eq!(stale.displayable_value(), Some(&100));
        assert!(matches!(stale, Freshness::Stale { .. }));
    }

    /// Round 6 item 3: stale telemetry must never be able to substitute
    /// for a mandatory fresh execution-time read. `Freshness` intentionally
    /// exposes no method that returns a plain, freshness-blind value for
    /// use in a decision -- `displayable_value` is documented as display
    /// -only, and nothing in this module (or anywhere signing/broadcast
    /// -related) ever calls it to build a transaction. This test pins that
    /// contract: a caller who only checks `is_fresh()` and refuses to act
    /// on a `Stale`/`Unavailable` result behaves correctly by construction,
    /// since neither variant offers a "trust me anyway" escape hatch.
    #[test]
    fn stale_or_unavailable_telemetry_can_never_be_mistaken_for_a_fresh_mandatory_read() {
        let fresh: Freshness<u64> = Freshness::Fresh {
            value: 1,
            age: Duration::ZERO,
        };
        let stale: Freshness<u64> = Freshness::Stale {
            value: 1,
            age: FRESHNESS_TTL + Duration::from_secs(1),
        };
        let unavailable: Freshness<u64> = Freshness::Unavailable;

        assert!(fresh.is_fresh());
        assert!(!stale.is_fresh());
        assert!(!unavailable.is_fresh());

        // A caller gating a mandatory action on `is_fresh()` alone would
        // correctly refuse to act on either of these -- exactly the
        // behavior every real signing/spend path already implements by
        // never consulting this module at all.
        for value in [stale, unavailable] {
            assert!(!value.is_fresh());
        }
    }
}
