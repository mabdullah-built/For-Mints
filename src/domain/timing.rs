//! Pure timing/phase-window math.
//!
//! No sleeping happens here. This module only computes *what* a scheduler
//! should do; `kairox` never busy-spins a CPU core to hit a deadline. Phase 2
//! is expected to consume [`CountdownPlan`] with real async sleeps.

use time::{Duration, OffsetDateTime};

/// A mint stage's `[start, end)` window, in UTC. `end: None` means the
/// protocol itself supplies no authoritative end -- never a placeholder
/// for "assume it ends eventually" or any invented timestamp (e.g. a
/// thirdweb Drop's last configured multi-phase condition, or any
/// single-phase condition, genuinely has no on-chain end field at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseWindow {
    pub start: OffsetDateTime,
    pub end: Option<OffsetDateTime>,
}

/// Where `now` sits relative to a [`PhaseWindow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageStatus {
    /// Stage has not opened yet; `starts_in` is always positive.
    NotStarted { starts_in: Duration },
    /// Stage is currently open. `ends_in` is `Some` (always positive)
    /// only when the window has a known end; `None` means genuinely
    /// open-ended -- never a large-but-finite stand-in duration.
    Active { ends_in: Option<Duration> },
    /// Stage has closed. Only reachable when the window has a known,
    /// already-passed end -- an open-ended window (`end: None`) can
    /// never become `Ended`.
    Ended,
}

impl PhaseWindow {
    /// Classify `now` against this window.
    pub fn status(&self, now: OffsetDateTime) -> StageStatus {
        if now < self.start {
            return StageStatus::NotStarted {
                starts_in: self.start - now,
            };
        }
        match self.end {
            Some(end) if now >= end => StageStatus::Ended,
            Some(end) => StageStatus::Active {
                ends_in: Some(end - now),
            },
            None => StageStatus::Active { ends_in: None },
        }
    }
}

/// A single segment of a countdown plan. Pure data — the caller decides how
/// (and whether) to actually sleep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepSegment {
    /// A coarse sleep, safe to interrupt/re-check periodically. Used for the
    /// bulk of a long wait.
    Coarse(Duration),
    /// A short, high-resolution final segment immediately before the
    /// deadline. Still an ordinary async sleep — never a busy-spin loop.
    Fine(Duration),
}

/// Above this remaining duration, sleep in coarse chunks capped at
/// [`COARSE_CHUNK`]. Below it, switch to the fine-grained final segment.
pub const FINE_WINDOW: Duration = Duration::milliseconds(1_500);
/// Maximum size of any single coarse sleep chunk, so a caller can re-check
/// external state (e.g. RPC-derived clock drift) periodically during a long
/// wait instead of sleeping through it blindly.
pub const COARSE_CHUNK: Duration = Duration::seconds(5);

/// Build a countdown plan from `now` to `target`.
///
/// Returns an empty plan if `target <= now`. Otherwise returns zero or more
/// [`SleepSegment::Coarse`] chunks (each `<= COARSE_CHUNK`) covering
/// everything more than [`FINE_WINDOW`] away from the target, followed by
/// exactly one [`SleepSegment::Fine`] covering the remainder.
pub fn plan_countdown(now: OffsetDateTime, target: OffsetDateTime) -> Vec<SleepSegment> {
    let mut remaining = target - now;
    if remaining <= Duration::ZERO {
        return Vec::new();
    }

    let mut segments = Vec::new();
    while remaining > FINE_WINDOW {
        let chunk = if remaining - FINE_WINDOW > COARSE_CHUNK {
            COARSE_CHUNK
        } else {
            remaining - FINE_WINDOW
        };
        segments.push(SleepSegment::Coarse(chunk));
        remaining -= chunk;
    }
    if remaining > Duration::ZERO {
        segments.push(SleepSegment::Fine(remaining));
    }
    segments
}

/// Signed drift between the local system clock and a remote-reported time
/// (e.g. a chain's latest block timestamp). Positive means the local clock
/// is ahead of the remote value.
pub fn clock_drift(local_utc: OffsetDateTime, remote_reported: OffsetDateTime) -> Duration {
    local_utc - remote_reported
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn window() -> PhaseWindow {
        PhaseWindow {
            start: datetime!(2026-08-16 12:00:00 UTC),
            end: Some(datetime!(2026-08-16 13:00:00 UTC)),
        }
    }

    #[test]
    fn status_not_started_before_window() {
        let status = window().status(datetime!(2026-08-16 11:59:00 UTC));
        assert_eq!(
            status,
            StageStatus::NotStarted {
                starts_in: Duration::minutes(1)
            }
        );
    }

    #[test]
    fn status_active_at_start_boundary() {
        let status = window().status(datetime!(2026-08-16 12:00:00 UTC));
        assert_eq!(
            status,
            StageStatus::Active {
                ends_in: Some(Duration::hours(1))
            }
        );
    }

    #[test]
    fn status_active_mid_window() {
        let status = window().status(datetime!(2026-08-16 12:30:00 UTC));
        assert_eq!(
            status,
            StageStatus::Active {
                ends_in: Some(Duration::minutes(30))
            }
        );
    }

    #[test]
    fn status_ended_at_end_boundary() {
        let status = window().status(datetime!(2026-08-16 13:00:00 UTC));
        assert_eq!(status, StageStatus::Ended);
    }

    #[test]
    fn status_open_ended_window_is_active_forever_with_no_ends_in() {
        let open = PhaseWindow {
            start: datetime!(2026-08-16 12:00:00 UTC),
            end: None,
        };
        assert_eq!(
            open.status(datetime!(2026-08-16 12:30:00 UTC)),
            StageStatus::Active { ends_in: None }
        );
        assert_eq!(
            open.status(datetime!(2099-01-01 00:00:00 UTC)),
            StageStatus::Active { ends_in: None },
            "an open-ended window must never transition to Ended, no matter how far in the \
             future -- there is no synthetic far-future end to cross"
        );
    }

    #[test]
    fn status_ended_after_window() {
        let status = window().status(datetime!(2026-08-16 14:00:00 UTC));
        assert_eq!(status, StageStatus::Ended);
    }

    #[test]
    fn plan_countdown_empty_when_target_in_past() {
        let now = datetime!(2026-08-16 12:00:00 UTC);
        let target = datetime!(2026-08-16 11:00:00 UTC);
        assert!(plan_countdown(now, target).is_empty());
    }

    #[test]
    fn plan_countdown_pure_fine_segment_when_close() {
        let now = datetime!(2026-08-16 12:00:00 UTC);
        let target = now + Duration::milliseconds(800);
        let segments = plan_countdown(now, target);
        assert_eq!(
            segments,
            vec![SleepSegment::Fine(Duration::milliseconds(800))]
        );
    }

    #[test]
    fn plan_countdown_splits_long_wait_into_coarse_chunks_plus_fine_tail() {
        let now = datetime!(2026-08-16 12:00:00 UTC);
        let target = now + Duration::seconds(12);
        let segments = plan_countdown(now, target);

        // 12s total, FINE_WINDOW=1.5s => 10.5s of coarse time, in <=5s chunks: 5s, 5s, 0.5s, then Fine(1.5s)
        assert_eq!(
            segments,
            vec![
                SleepSegment::Coarse(Duration::seconds(5)),
                SleepSegment::Coarse(Duration::seconds(5)),
                SleepSegment::Coarse(Duration::milliseconds(500)),
                SleepSegment::Fine(Duration::milliseconds(1_500)),
            ]
        );

        let total: Duration = segments
            .iter()
            .map(|s| match s {
                SleepSegment::Coarse(d) | SleepSegment::Fine(d) => *d,
            })
            .fold(Duration::ZERO, |acc, d| acc + d);
        assert_eq!(total, Duration::seconds(12));
    }

    #[test]
    fn plan_countdown_never_produces_negative_or_zero_segments() {
        let now = datetime!(2026-08-16 12:00:00 UTC);
        for millis in [1, 100, 1_499, 1_500, 1_501, 5_000, 5_001, 30_000, 123_456] {
            let target = now + Duration::milliseconds(millis);
            for segment in plan_countdown(now, target) {
                let d = match segment {
                    SleepSegment::Coarse(d) | SleepSegment::Fine(d) => d,
                };
                assert!(
                    d > Duration::ZERO,
                    "segment must be strictly positive: {d:?}"
                );
            }
        }
    }

    #[test]
    fn clock_drift_positive_when_local_ahead() {
        let local = datetime!(2026-08-16 12:00:05 UTC);
        let remote = datetime!(2026-08-16 12:00:00 UTC);
        assert_eq!(clock_drift(local, remote), Duration::seconds(5));
    }

    #[test]
    fn clock_drift_negative_when_local_behind() {
        let local = datetime!(2026-08-16 12:00:00 UTC);
        let remote = datetime!(2026-08-16 12:00:05 UTC);
        assert_eq!(clock_drift(local, remote), Duration::seconds(-5));
    }
}
