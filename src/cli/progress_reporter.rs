//! A bounded, non-blocking cosmetic-progress reporter.
//!
//! `run_live_mint`/`run_opensea_mint`/`wait_for_stage` all take a plain
//! synchronous `impl FnMut(Progress)` callback, called inline on the
//! dispatch-critical path. Before this module existed, every caller's
//! callback did a direct, synchronous `eprintln!` -- which meant a
//! stalled stderr consumer (a full OS pipe buffer from a non-reading
//! downstream process) could theoretically block that callback, and
//! therefore the mandatory work sitting right next to it in the same
//! synchronous call stack.
//!
//! [`ProgressReporter`] decouples "the hot path decided something
//! happened" from "a line gets printed for it": the hot path only ever
//! calls [`ProgressReporter::emit`], which is a non-blocking, non-async,
//! infallible-from-the-caller's-perspective `try_send` into a bounded
//! channel -- never awaited, never retried, and silently a no-op if the
//! queue is full or the consumer is gone. A separate, dedicated consumer
//! task owns all the actual terminal I/O, running independently of
//! whatever the hot path is doing.
//!
//! This is deliberately not a logging framework: no levels, no
//! formatting pipeline, no destinations beyond stderr. Just a bounded
//! queue and a task that drains it.

use std::time::Duration;

/// How many pending progress events may queue up before new ones are
/// silently dropped. Generous for a normal terminal (which drains in
/// microseconds), small enough that a permanently-stalled consumer can
/// never accumulate unbounded memory.
const DEFAULT_CAPACITY: usize = 64;

/// How long [`ProgressReporter::finish`] will wait for the consumer task
/// to drain whatever was already queued, once the hot path has already
/// finished. Never called before dispatch -- only as a final,
/// best-effort flush so the last few summary lines aren't lost. Bounded
/// so a stalled consumer can never hang the process on exit either.
const FINISH_TIMEOUT: Duration = Duration::from_millis(500);

/// A non-blocking emitter for cosmetic progress events of type `T`,
/// backed by a dedicated consumer task that owns the real rendering.
pub struct ProgressReporter<T: Send + 'static> {
    tx: tokio::sync::mpsc::Sender<T>,
    handle: tokio::task::JoinHandle<()>,
}

impl<T: Send + 'static> ProgressReporter<T> {
    /// Spawns the dedicated consumer task. `render` is called once per
    /// event, in emission order, until every [`ProgressReporter`] handle
    /// (and every clone of its sender, if any existed) is dropped. A
    /// panic inside `render` ends the consumer task; subsequent `emit`
    /// calls simply become no-ops (a dead reporter is exactly as safe as
    /// a full one -- neither can affect the caller).
    pub fn spawn(render: impl FnMut(T) + Send + 'static) -> Self {
        Self::spawn_with_capacity(DEFAULT_CAPACITY, render)
    }

    pub fn spawn_with_capacity(
        capacity: usize,
        mut render: impl FnMut(T) + Send + 'static,
    ) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel(capacity);
        let handle = tokio::spawn(async move {
            while let Some(item) = rx.recv().await {
                render(item);
            }
        });
        Self { tx, handle }
    }

    /// Non-blocking, best-effort emit -- never awaits, never blocks,
    /// never retries on a full queue or a dead consumer. This is the
    /// *only* method the dispatch-critical path is ever allowed to call.
    pub fn emit(&self, item: T) {
        let _ = self.tx.try_send(item);
    }

    /// Best-effort final flush, only ever called *after* execution has
    /// already completed (never on the dispatch-critical path itself):
    /// drops this reporter's sender so the consumer's `recv()` loop ends
    /// once the queue drains, then waits up to [`FINISH_TIMEOUT`] for
    /// that to happen. A consumer that is somehow still stuck after the
    /// timeout is simply abandoned -- shutdown must never hang the
    /// process.
    pub async fn finish(self) {
        drop(self.tx);
        let _ = tokio::time::timeout(FINISH_TIMEOUT, self.handle).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn emit_never_blocks_even_when_the_consumer_stalls_for_two_seconds() {
        let started_consuming = Arc::new(tokio::sync::Notify::new());
        let started_consuming_for_render = started_consuming.clone();
        let reporter = ProgressReporter::spawn_with_capacity(4, move |_item: u32| {
            started_consuming_for_render.notify_one();
            std::thread::sleep(Duration::from_secs(2));
        });

        // Let the consumer actually pick up the first item and start
        // "stalling" before we measure emit()'s own latency.
        reporter.emit(1);
        started_consuming.notified().await;

        let started = std::time::Instant::now();
        reporter.emit(2);
        reporter.emit(3);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(100),
            "emit() must never block on a stalled consumer, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_full_queue_never_blocks_the_producer_and_execution_continues() {
        let reporter = ProgressReporter::spawn_with_capacity(1, |_item: u32| {
            // Never drains -- simulates a permanently full queue.
            std::thread::sleep(Duration::from_secs(10));
        });

        let started = std::time::Instant::now();
        for i in 0..50 {
            reporter.emit(i);
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(200),
            "50 emits against a full/blocked queue must all return immediately, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_panicking_or_exited_consumer_never_affects_the_producer() {
        let reporter = ProgressReporter::spawn_with_capacity(4, |item: u32| {
            if item == 1 {
                panic!("simulated consumer panic");
            }
        });

        reporter.emit(1);
        // Give the consumer task a moment to actually panic and exit.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The consumer task is now dead. Further emits must still be
        // silent no-ops, never a panic or block in the caller.
        let started = std::time::Instant::now();
        reporter.emit(2);
        reporter.emit(3);
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn emitted_events_are_actually_rendered_under_normal_operation() {
        let rendered = Arc::new(AtomicU32::new(0));
        let rendered_for_render = rendered.clone();
        let reporter = ProgressReporter::spawn(move |item: u32| {
            rendered_for_render.fetch_add(item, Ordering::SeqCst);
        });

        reporter.emit(1);
        reporter.emit(2);
        reporter.emit(3);
        reporter.finish().await;

        assert_eq!(rendered.load(Ordering::SeqCst), 6);
    }

    /// Final hardening pass item 9: measure `emit()`'s own overhead
    /// (never the consumer's rendering time, which is independent) under
    /// three conditions -- consumer draining immediately, consumer
    /// permanently stalled, and no consumer at all (channel already
    /// closed). No fragile microsecond gate: just a generous upper bound
    /// and a printed median/p90/p95 for a human to read, proving overhead
    /// stays negligible and independent of how fast anything downstream
    /// consumes.
    // A permanently-stalled consumer occupies one worker thread forever
    // (matching real production, where the runtime is multi-threaded via
    // `#[tokio::main]`) -- the default single-threaded `#[tokio::test]`
    // runtime would starve the test's own task behind it, since a
    // synchronous, never-yielding closure can't be preempted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn emit_overhead_is_negligible_and_independent_of_consumer_speed() {
        fn percentiles(mut samples: Vec<u128>) -> (u128, u128, u128) {
            samples.sort_unstable();
            let at = |p: f64| samples[((samples.len() - 1) as f64 * p).round() as usize];
            (at(0.5), at(0.9), at(0.95))
        }

        const SAMPLES: usize = 500;

        // Condition 1: consumer draining immediately.
        let draining = ProgressReporter::spawn(|_item: u32| {});
        let mut draining_ns = Vec::with_capacity(SAMPLES);
        for i in 0..SAMPLES as u32 {
            let started = std::time::Instant::now();
            draining.emit(i);
            draining_ns.push(started.elapsed().as_nanos());
        }
        draining.finish().await;

        // Condition 2: consumer permanently stalled (first item blocks it
        // forever; the bounded queue behind it fills and every emit past
        // that point is a guaranteed-full try_send).
        let stalled = ProgressReporter::spawn_with_capacity(1, |_item: u32| {
            // Long enough to stay stalled for this test's entire
            // measurement window (well under a second), short enough
            // that a torn-down runtime's worker thread doesn't linger
            // past the test process's own lifetime by much.
            std::thread::sleep(Duration::from_secs(2));
        });
        stalled.emit(0); // occupies the consumer thread
        tokio::time::sleep(Duration::from_millis(20)).await; // let it actually start
        let mut stalled_ns = Vec::with_capacity(SAMPLES);
        for i in 0..SAMPLES as u32 {
            let started = std::time::Instant::now();
            stalled.emit(i);
            stalled_ns.push(started.elapsed().as_nanos());
        }

        // Condition 3: no consumer at all (its task already exited, e.g.
        // panicked) -- `tx` is still alive so `emit()` still runs its
        // real try_send path, just against a permanently-closed channel.
        let disabled = ProgressReporter::spawn(|_item: u32| panic!("consumer exits immediately"));
        disabled.emit(0);
        tokio::time::sleep(Duration::from_millis(20)).await; // let it actually exit
        let mut disabled_ns = Vec::with_capacity(SAMPLES);
        for i in 0..SAMPLES as u32 {
            let started = std::time::Instant::now();
            disabled.emit(i);
            disabled_ns.push(started.elapsed().as_nanos());
        }

        let (d_p50, d_p90, d_p95) = percentiles(draining_ns);
        let (s_p50, s_p90, s_p95) = percentiles(stalled_ns);
        let (x_p50, x_p90, x_p95) = percentiles(disabled_ns);
        println!(
            "emit() overhead (ns): draining p50={d_p50} p90={d_p90} p95={d_p95} | \
             stalled p50={s_p50} p90={s_p90} p95={s_p95} | \
             disabled p50={x_p50} p90={x_p90} p95={x_p95}"
        );

        // Generous, never fragile: emit() is a single try_send, so even a
        // slow CI box should stay several orders of magnitude under 1ms.
        for p95 in [d_p95, s_p95, x_p95] {
            assert!(
                p95 < 1_000_000,
                "emit() p95 overhead should be well under 1ms regardless of consumer state, \
                 got {p95}ns"
            );
        }
    }
}
