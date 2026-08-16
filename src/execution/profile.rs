//! Per-chain execution profiles: the single place chain-specific timing,
//! benchmarking, and health-policy behavior is expressed, so no
//! chain-specific `if chain_id == ...` conditionals need to be scattered
//! through the rest of the execution engine.

use std::time::Duration as StdDuration;

use time::Duration;

use crate::chain::benchmark::{BenchmarkConfig, HealthPolicy};
use crate::chain::registry::ChainId;

use super::scheduler::SchedulerTimings;

/// Everything about *how* Kairox executes a live mint that legitimately
/// varies by chain: how aggressively to benchmark, how long before
/// stage-open to run each scheduler checkpoint, and how strict the
/// endpoint health policy is.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExecutionProfile {
    pub chain_id: ChainId,
    pub scheduler_policy: SchedulerTimings,
    pub benchmark_policy: BenchmarkConfig,
    pub health_policy: HealthPolicy,
    /// How long before the state-check checkpoint to run connect+benchmark
    /// (prewarming). Kept separate from `scheduler_policy.state_check_lead`
    /// so prewarming can start earlier than the first real state read.
    pub prewarm_lead: Duration,
    pub receipt_poll_interval: StdDuration,
    pub receipt_timeout: StdDuration,
}

/// Robinhood Chain (id 4663) is Phase 3's priority chain: direct sequencer
/// submission is expected to be available and fast, so benchmarking is
/// cheap (fewer, quicker samples) and the scheduler leads are tighter.
fn robinhood() -> ExecutionProfile {
    ExecutionProfile {
        chain_id: 4663,
        scheduler_policy: SchedulerTimings {
            state_check_lead: Duration::seconds(6),
            refresh_lead: Duration::seconds(2),
            finalize_lead: Duration::milliseconds(600),
        },
        benchmark_policy: BenchmarkConfig {
            sample_count: 4,
            sample_delay: StdDuration::from_millis(30),
        },
        health_policy: HealthPolicy::default(),
        prewarm_lead: Duration::seconds(8),
        receipt_poll_interval: StdDuration::from_millis(400),
        receipt_timeout: StdDuration::from_secs(30),
    }
}

/// Base (id 8453): fast L2 block times, but public RPC latency is more
/// variable than a direct sequencer — slightly wider leads than Robinhood,
/// more samples to smooth out that variance.
fn base() -> ExecutionProfile {
    ExecutionProfile {
        chain_id: 8453,
        scheduler_policy: SchedulerTimings {
            state_check_lead: Duration::seconds(8),
            refresh_lead: Duration::seconds(2),
            finalize_lead: Duration::seconds(1),
        },
        benchmark_policy: BenchmarkConfig {
            sample_count: 5,
            sample_delay: StdDuration::from_millis(50),
        },
        health_policy: HealthPolicy::default(),
        prewarm_lead: Duration::seconds(10),
        receipt_poll_interval: StdDuration::from_millis(600),
        receipt_timeout: StdDuration::from_secs(45),
    }
}

/// Ethereum L1 (id 1): 12s block times and the highest financial stakes —
/// the most conservative leads and the most benchmark samples, since a
/// wrong read-endpoint choice here is the most expensive to get wrong.
fn ethereum() -> ExecutionProfile {
    ExecutionProfile {
        chain_id: 1,
        scheduler_policy: SchedulerTimings::default(),
        benchmark_policy: BenchmarkConfig {
            sample_count: 6,
            sample_delay: StdDuration::from_millis(75),
        },
        health_policy: HealthPolicy::default(),
        prewarm_lead: Duration::seconds(12),
        receipt_poll_interval: StdDuration::from_millis(750),
        receipt_timeout: StdDuration::from_secs(60),
    }
}

/// A conservative, chain-agnostic default for any chain without a
/// dedicated profile above (matches Phase 2's original defaults exactly).
fn generic(chain_id: ChainId) -> ExecutionProfile {
    ExecutionProfile {
        chain_id,
        scheduler_policy: SchedulerTimings::default(),
        benchmark_policy: BenchmarkConfig::default(),
        health_policy: HealthPolicy::default(),
        prewarm_lead: Duration::seconds(10),
        receipt_poll_interval: StdDuration::from_millis(750),
        receipt_timeout: StdDuration::from_secs(60),
    }
}

impl ExecutionProfile {
    /// The execution profile for `chain_id`. Chain-specific behavior lives
    /// entirely here — nowhere else in the codebase branches on a raw
    /// chain id for execution-timing purposes.
    pub fn for_chain(chain_id: ChainId) -> Self {
        match chain_id {
            4663 => robinhood(),
            8453 => base(),
            1 => ethereum(),
            other => generic(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robinhood_profile_has_expected_chain_id() {
        assert_eq!(ExecutionProfile::for_chain(4663).chain_id, 4663);
    }

    #[test]
    fn base_profile_has_expected_chain_id() {
        assert_eq!(ExecutionProfile::for_chain(8453).chain_id, 8453);
    }

    #[test]
    fn ethereum_profile_has_expected_chain_id() {
        assert_eq!(ExecutionProfile::for_chain(1).chain_id, 1);
    }

    #[test]
    fn unknown_chain_gets_generic_profile_matching_defaults() {
        let profile = ExecutionProfile::for_chain(999_999);
        assert_eq!(profile.chain_id, 999_999);
        assert_eq!(profile.scheduler_policy, SchedulerTimings::default());
        assert_eq!(profile.benchmark_policy, BenchmarkConfig::default());
    }

    #[test]
    fn robinhood_leads_are_tighter_than_ethereum() {
        let rh = ExecutionProfile::for_chain(4663);
        let eth = ExecutionProfile::for_chain(1);
        assert!(rh.scheduler_policy.finalize_lead < eth.scheduler_policy.finalize_lead);
        assert!(rh.prewarm_lead < eth.prewarm_lead);
    }

    #[test]
    fn every_named_profile_keeps_scheduler_checkpoints_ordered() {
        for chain_id in [1u64, 8453, 4663, 42] {
            let profile = ExecutionProfile::for_chain(chain_id);
            let checkpoints = profile.scheduler_policy.checkpoints();
            assert!(checkpoints[0].1 > checkpoints[1].1);
            assert!(checkpoints[1].1 > checkpoints[2].1);
        }
    }
}
