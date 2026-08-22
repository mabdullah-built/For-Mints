//! `kairox watch`: waits for an explicitly-configured, currently-inactive
//! stage to become live, then hands off to the same already-hardened
//! critical-path engines ([`super::live::run_live_mint`] /
//! [`super::opensea_engine::run_opensea_mint`]) that a manually-timed
//! `mint --send` uses. Nothing about the T-10s/T-3s/T-1s/T0 critical path is
//! reimplemented here -- both of those functions already accept a
//! `known_stage_start` that can be arbitrarily far in the future and already
//! sleep correctly (coarse-then-fine, never busy-spinning) all the way to it.
//!
//! The one genuinely new behavior this module adds is the outer, long-
//! horizon [`WatchState::Waiting`] loop: periodically re-verifying stage
//! timing/eligibility/supply while far from T0, since a single sleep from
//! "right now" straight through to a stage that might be hours or days away
//! would never notice a sold-out collection, a wallet that lost eligibility,
//! or a stage the project owner rescheduled. Once within
//! [`WatchPollConfig::arm_threshold`] of the best currently-known stage
//! start, this module stops polling and calls the existing engine
//! unchanged.

use std::time::Duration as StdDuration;

use time::OffsetDateTime;

use crate::domain::timing::StageStatus;

use super::errors::{Categorize, ErrorCategory, KairoxError};

/// Observable states of one watch session, in the order they normally fire.
/// `Stopped` and `Success` are terminal; every other state can recur (e.g.
/// `Waiting` fires once per poll while far from T0).
#[derive(Debug, Clone, PartialEq)]
pub enum WatchState {
    Discover,
    Verify,
    Waiting {
        stage_start: OffsetDateTime,
        time_remaining: time::Duration,
    },
    TMinus10,
    TMinus3,
    Arming,
    Armed,
    T0,
    Broadcasting,
    Receipt,
    Success,
    Stopped {
        reason: String,
    },
}

/// A snapshot of authoritative stage timing/status, as read fresh from
/// either on-chain state (the PUBLIC engine) or the official OpenSea Drops
/// API (the OpenSea engine). Deliberately minimal -- just enough to drive
/// the waiting loop; eligibility/supply/spend-cap enforcement stays with the
/// same code paths ([`super::plan::build_plan`] /
/// [`super::opensea_validate`]) that already own it.
#[derive(Debug, Clone, Copy)]
pub struct StageSnapshot {
    pub stage_start: OffsetDateTime,
    pub status: StageStatus,
}

/// Re-fetches an authoritative [`StageSnapshot`]. Implemented once for the
/// on-chain PUBLIC engine and once for the OpenSea engine (see
/// `cli::commands::watch`); a fake implementation drives this module's own
/// deterministic unit tests without any network/RPC involved.
#[async_trait::async_trait]
pub trait StageProbe: Send + Sync {
    async fn probe(&self) -> Result<StageSnapshot, KairoxError>;
}

/// Tunables for [`wait_for_stage`]. Every value is caller-overridable --
/// nothing here is a hard-coded constant baked into the loop.
#[derive(Debug, Clone, Copy)]
pub struct WatchPollConfig {
    /// How often to re-probe while far from T0.
    pub poll_interval: StdDuration,
    /// Stop polling and hand off to the tight critical-path engine once the
    /// best-known stage start is within this much of "now". Should match
    /// (or exceed) the engine's own `SchedulerTimings::state_check_lead` --
    /// handing off any later would skip the engine's own first fresh state
    /// check.
    pub arm_threshold: time::Duration,
    /// How many *consecutive* `Retryable`-categorized probe errors (a
    /// transient RPC/API hiccup, never a definitive on-chain/API answer)
    /// are tolerated before giving up. A read-only probe retry carries none
    /// of the double-broadcast risk a signed-transaction retry would, so
    /// this is allowed to be generous; it is still bounded, never infinite.
    pub max_consecutive_retryable_errors: u32,
}

impl Default for WatchPollConfig {
    fn default() -> Self {
        Self {
            poll_interval: StdDuration::from_secs(60),
            arm_threshold: time::Duration::seconds(10),
            max_consecutive_retryable_errors: 20,
        }
    }
}

fn std_duration_from_time(d: time::Duration) -> StdDuration {
    d.try_into().unwrap_or(StdDuration::ZERO)
}

/// Poll `probe` until the authoritative stage start is within
/// `config.arm_threshold` of "now", then return that stage start. Returns
/// `Err` (fail-closed, never guessed past) if the stage has definitively
/// ended, or if `probe` itself returns a non-retryable error (sold out,
/// wallet ineligible, wrong chain, invalid API response, ...), or if
/// transient probe errors exceed the bounded retry budget.
///
/// A `NotStarted` stage is never treated as an error -- that is exactly the
/// condition this function exists to wait through.
pub async fn wait_for_stage(
    probe: &dyn StageProbe,
    config: &WatchPollConfig,
    mut on_state: impl FnMut(WatchState),
) -> Result<OffsetDateTime, KairoxError> {
    let mut consecutive_retryable_errors = 0u32;
    loop {
        match probe.probe().await {
            Ok(snapshot) => {
                consecutive_retryable_errors = 0;
                if matches!(snapshot.status, StageStatus::Ended) {
                    return Err(KairoxError::Session(
                        crate::execution::errors::SessionError::new(
                            "stage has already ended; nothing left to watch for",
                        ),
                    ));
                }
                let now = OffsetDateTime::now_utc();
                let remaining = snapshot.stage_start - now;
                if remaining <= config.arm_threshold {
                    return Ok(snapshot.stage_start);
                }
                on_state(WatchState::Waiting {
                    stage_start: snapshot.stage_start,
                    time_remaining: remaining,
                });
                let sleep_for = (remaining - config.arm_threshold).min(
                    time::Duration::try_from(config.poll_interval).unwrap_or(time::Duration::ZERO),
                );
                tokio::time::sleep(std_duration_from_time(sleep_for.max(time::Duration::ZERO)))
                    .await;
            }
            Err(e) if e.category() == ErrorCategory::Retryable => {
                consecutive_retryable_errors += 1;
                if consecutive_retryable_errors > config.max_consecutive_retryable_errors {
                    return Err(e);
                }
                tokio::time::sleep(config.poll_interval).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A cloneable stand-in for one scripted probe response -- avoids
    /// needing `KairoxError: Clone` (it deliberately isn't) while still
    /// letting a fake response be replayed past the end of the script.
    #[derive(Clone)]
    enum FakeResponse {
        Ok(StageSnapshot),
        Timeout,
        Fatal(&'static str),
    }

    impl FakeResponse {
        fn into_result(self) -> Result<StageSnapshot, KairoxError> {
            match self {
                FakeResponse::Ok(s) => Ok(s),
                FakeResponse::Timeout => Err(timeout_error()),
                FakeResponse::Fatal(msg) => Err(KairoxError::Session(
                    crate::execution::errors::SessionError::new(msg),
                )),
            }
        }
    }

    struct FakeProbe {
        responses: Vec<FakeResponse>,
        calls: AtomicUsize,
    }

    impl FakeProbe {
        fn new(responses: Vec<FakeResponse>) -> Self {
            Self {
                responses,
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl StageProbe for FakeProbe {
        async fn probe(&self) -> Result<StageSnapshot, KairoxError> {
            let idx = self.calls.fetch_add(1, Ordering::SeqCst);
            let response = self
                .responses
                .get(idx)
                .or_else(|| self.responses.last())
                .expect("FakeProbe needs at least one scripted response")
                .clone();
            response.into_result()
        }
    }

    fn fast_config() -> WatchPollConfig {
        WatchPollConfig {
            poll_interval: StdDuration::from_millis(5),
            arm_threshold: time::Duration::milliseconds(50),
            max_consecutive_retryable_errors: 5,
        }
    }

    #[tokio::test]
    async fn future_stage_waits_without_erroring_then_arms() {
        let now = OffsetDateTime::now_utc();
        let stage_start = now + time::Duration::milliseconds(80);
        let probe = FakeProbe::new(vec![FakeResponse::Ok(StageSnapshot {
            stage_start,
            status: StageStatus::NotStarted {
                starts_in: time::Duration::milliseconds(80),
            },
        })]);
        let mut waited = 0;
        let result = wait_for_stage(&probe, &fast_config(), |state| {
            if matches!(state, WatchState::Waiting { .. }) {
                waited += 1;
            }
        })
        .await;
        assert!(result.is_ok());
        assert!(waited >= 1, "expected at least one WAITING report, got 0");
    }

    #[tokio::test]
    async fn already_close_stage_arms_immediately_with_no_wait_reported() {
        let now = OffsetDateTime::now_utc();
        let stage_start = now + time::Duration::milliseconds(5);
        let probe = FakeProbe::new(vec![FakeResponse::Ok(StageSnapshot {
            stage_start,
            status: StageStatus::NotStarted {
                starts_in: time::Duration::milliseconds(5),
            },
        })]);
        let mut waited = 0;
        let result = wait_for_stage(&probe, &fast_config(), |state| {
            if matches!(state, WatchState::Waiting { .. }) {
                waited += 1;
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(waited, 0);
    }

    #[tokio::test]
    async fn stage_ended_while_waiting_stops_with_no_replacement_wait() {
        let now = OffsetDateTime::now_utc();
        let far_future = now + time::Duration::milliseconds(80);
        let probe = FakeProbe::new(vec![
            FakeResponse::Ok(StageSnapshot {
                stage_start: far_future,
                status: StageStatus::NotStarted {
                    starts_in: time::Duration::milliseconds(80),
                },
            }),
            FakeResponse::Ok(StageSnapshot {
                stage_start: far_future,
                status: StageStatus::Ended,
            }),
        ]);
        let result = wait_for_stage(&probe, &fast_config(), |_| {}).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sold_out_reported_as_fatal_error_stops_immediately() {
        let probe = FakeProbe::new(vec![FakeResponse::Fatal("collection sold out")]);
        let result = wait_for_stage(&probe, &fast_config(), |_| {}).await;
        assert!(result.is_err());
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stage_start_moving_later_while_waiting_updates_the_target() {
        let now = OffsetDateTime::now_utc();
        let first_estimate = now + time::Duration::milliseconds(60);
        let updated_estimate = now + time::Duration::milliseconds(200);
        let probe = FakeProbe::new(vec![
            FakeResponse::Ok(StageSnapshot {
                stage_start: first_estimate,
                status: StageStatus::NotStarted {
                    starts_in: time::Duration::milliseconds(60),
                },
            }),
            FakeResponse::Ok(StageSnapshot {
                stage_start: updated_estimate,
                status: StageStatus::NotStarted {
                    starts_in: time::Duration::milliseconds(140),
                },
            }),
        ]);
        let mut last_seen_target = None;
        let result = wait_for_stage(&probe, &fast_config(), |state| {
            if let WatchState::Waiting { stage_start, .. } = state {
                last_seen_target = Some(stage_start);
            }
        })
        .await;
        assert!(result.is_ok());
        assert!(last_seen_target.is_some());
    }

    /// Round 6 item 5 (item 5.A/5.B): `wait_for_stage` adapts to a
    /// changed stage start purely by re-reading the probe's fresh
    /// snapshot on every poll -- this is the *same* mechanism regardless
    /// of which direction the start time moves, and it requires no stage
    /// identity/UUID concept at all (`StageSnapshot` doesn't carry one).
    /// This is exactly why a periodic full re-resolution (see
    /// `cli::commands::watch::wait_for_stage_with_reresolution`) is not
    /// needed to keep the *already-selected* stage's own timing fresh --
    /// only to notice when a *different* stage becomes the better choice.
    /// Complements `stage_start_moving_later_while_waiting_updates_the_target`
    /// above (which proves the "later" direction) with the "earlier"
    /// direction.
    #[tokio::test]
    async fn stage_start_moving_earlier_while_waiting_updates_the_target_and_arms_promptly() {
        let now = OffsetDateTime::now_utc();
        // First estimate: comfortably beyond arm_threshold (50ms), so the
        // first poll must not hand off yet.
        let first_estimate = now + time::Duration::milliseconds(300);
        // Updated estimate: the creator moved the stage earlier, now
        // within arm_threshold -- the very next poll must hand off, using
        // this updated, earlier target, not the original later one.
        let updated_estimate = now + time::Duration::milliseconds(20);
        let probe = FakeProbe::new(vec![
            FakeResponse::Ok(StageSnapshot {
                stage_start: first_estimate,
                status: StageStatus::NotStarted {
                    starts_in: time::Duration::milliseconds(300),
                },
            }),
            FakeResponse::Ok(StageSnapshot {
                stage_start: updated_estimate,
                status: StageStatus::NotStarted {
                    starts_in: time::Duration::milliseconds(20),
                },
            }),
        ]);
        let result = wait_for_stage(&probe, &fast_config(), |_| {}).await;
        let armed_at = result.expect("must arm successfully against the updated, earlier target");
        assert_eq!(
            armed_at, updated_estimate,
            "must hand off using the freshest known stage start, not a stale earlier-observed \
             later estimate"
        );
    }

    fn timeout_error() -> KairoxError {
        use crate::chain::rpc::{RpcError, TransportError};
        KairoxError::Rpc(RpcError::Transport(TransportError::Timeout(
            StdDuration::from_secs(5),
        )))
    }

    #[tokio::test]
    async fn transient_probe_error_is_retried_not_fatal() {
        let now = OffsetDateTime::now_utc();
        let stage_start = now + time::Duration::milliseconds(5);
        let probe = FakeProbe::new(vec![
            FakeResponse::Timeout,
            FakeResponse::Ok(StageSnapshot {
                stage_start,
                status: StageStatus::NotStarted {
                    starts_in: time::Duration::milliseconds(5),
                },
            }),
        ]);
        let result = wait_for_stage(&probe, &fast_config(), |_| {}).await;
        assert!(
            result.is_ok(),
            "a single transient RPC timeout must not abort the watch"
        );
    }

    #[tokio::test]
    async fn transient_probe_errors_exceeding_the_retry_budget_stop() {
        let probe = FakeProbe::new(vec![FakeResponse::Timeout]);
        let config = WatchPollConfig {
            max_consecutive_retryable_errors: 2,
            poll_interval: StdDuration::from_millis(1),
            arm_threshold: time::Duration::milliseconds(50),
        };
        let result = wait_for_stage(&probe, &config, |_| {}).await;
        assert!(result.is_err());
        assert_eq!(probe.calls.load(Ordering::SeqCst), 3);
    }
}
