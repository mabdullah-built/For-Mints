//! Monotonic-safe waiting for a stage-open instant. No busy-spin loop
//! anywhere: waits are ordinary async sleeps, chunked via
//! [`crate::domain::timing::plan_countdown`] so long waits stay
//! interruptible/observable instead of blocking through in one sleep.

use time::{Duration, OffsetDateTime};

use crate::domain::timing::{SleepSegment, plan_countdown};

/// Configurable lead times before a target instant, in the order Kairox
/// acts on them (largest lead first). Defaults follow the T-10s/T-3s/T-1s
/// shape described in the Phase 2 design, but every value is
/// caller-overridable — nothing here is a hard-coded immutable constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerTimings {
    /// Lead time for the initial, lightweight state/eligibility check.
    pub state_check_lead: Duration,
    /// Lead time for refreshing nonce/fee/balance/supply and building the
    /// first candidate [`crate::execution::prepared::PreparedTransaction`].
    pub refresh_lead: Duration,
    /// Lead time for the final refresh + sign + serialize pass, whose
    /// output is exactly what gets broadcast at T=0.
    pub finalize_lead: Duration,
}

impl Default for SchedulerTimings {
    fn default() -> Self {
        Self {
            state_check_lead: Duration::seconds(10),
            refresh_lead: Duration::seconds(3),
            finalize_lead: Duration::seconds(1),
        }
    }
}

/// A named checkpoint before the broadcast instant, latest-first is not
/// assumed — [`SchedulerTimings::checkpoints`] returns them in the order
/// they should fire (largest lead time / earliest in wall-clock time
/// first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checkpoint {
    StateCheck,
    Refresh,
    Finalize,
}

impl SchedulerTimings {
    /// `(checkpoint, lead)` pairs sorted so the earliest-firing checkpoint
    /// (largest lead) comes first. Non-positive or duplicate leads are kept
    /// as given — callers pass sane configuration; this function does not
    /// second-guess it.
    pub fn checkpoints(&self) -> Vec<(Checkpoint, Duration)> {
        let mut v = vec![
            (Checkpoint::StateCheck, self.state_check_lead),
            (Checkpoint::Refresh, self.refresh_lead),
            (Checkpoint::Finalize, self.finalize_lead),
        ];
        v.sort_by_key(|(_, lead)| std::cmp::Reverse(*lead));
        v
    }
}

/// Sleep from `now` until `target`, in coarse-then-fine chunks, invoking
/// `on_segment` before each chunk so a caller can observe/report progress.
/// Never busy-spins: every chunk is a real `tokio::time::sleep`.
pub async fn sleep_until(
    now: OffsetDateTime,
    target: OffsetDateTime,
    mut on_segment: impl FnMut(SleepSegment),
) {
    for segment in plan_countdown(now, target) {
        on_segment(segment);
        let millis = match segment {
            SleepSegment::Coarse(d) | SleepSegment::Fine(d) => d,
        }
        .whole_milliseconds()
        .max(0) as u64;
        tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_timings_are_ordered_state_check_refresh_finalize() {
        let timings = SchedulerTimings::default();
        let checkpoints = timings.checkpoints();
        assert_eq!(checkpoints[0].0, Checkpoint::StateCheck);
        assert_eq!(checkpoints[1].0, Checkpoint::Refresh);
        assert_eq!(checkpoints[2].0, Checkpoint::Finalize);
        assert!(checkpoints[0].1 > checkpoints[1].1);
        assert!(checkpoints[1].1 > checkpoints[2].1);
    }

    #[test]
    fn checkpoints_are_configurable_not_fixed() {
        let timings = SchedulerTimings {
            state_check_lead: Duration::seconds(30),
            refresh_lead: Duration::seconds(6),
            finalize_lead: Duration::seconds(2),
        };
        let checkpoints = timings.checkpoints();
        assert_eq!(checkpoints[0].1, Duration::seconds(30));
        assert_eq!(checkpoints[2].1, Duration::seconds(2));
    }

    #[tokio::test]
    async fn sleep_until_returns_immediately_for_past_target() {
        let now = OffsetDateTime::now_utc();
        let target = now - Duration::seconds(5);
        let mut segments_seen = 0;
        sleep_until(now, target, |_| segments_seen += 1).await;
        assert_eq!(segments_seen, 0);
    }

    #[tokio::test]
    async fn sleep_until_invokes_on_segment_and_completes_near_target() {
        let now = OffsetDateTime::now_utc();
        let target = now + Duration::milliseconds(20);
        let mut segments_seen = 0;
        sleep_until(now, target, |_| segments_seen += 1).await;
        assert!(segments_seen >= 1);
        assert!(OffsetDateTime::now_utc() >= target - Duration::milliseconds(5));
    }
}
