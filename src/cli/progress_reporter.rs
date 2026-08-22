//! A bounded, non-blocking cosmetic-progress reporter whose consumer runs
//! entirely off the Tokio runtime.
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
//! An earlier version of this module fixed the *producer* side (a
//! bounded, non-blocking `try_send`) but ran the *consumer* -- the thing
//! that actually performs the blocking terminal I/O -- as an ordinary
//! Tokio task. That is not a complete fix: a Tokio task that calls a
//! genuinely blocking, non-yielding operation (like a real stalled
//! `eprintln!`) occupies whatever OS thread the runtime scheduled it on.
//! On a single-worker-thread runtime that thread *is* the one driving
//! mint execution, so the isolation was incomplete -- provable by the
//! fact that testing it honestly required forcing a multi-thread runtime
//! just to keep the stalled consumer off the test's own task.
//!
//! [`ProgressReporter`] now spawns a **dedicated `std::thread`** for the
//! consumer -- not a Tokio task, not `spawn_blocking` (which still draws
//! from a Tokio-managed thread pool with its own shutdown/backpressure
//! behavior this module has no need to reason about). The hot path only
//! ever calls [`ProgressReporter::emit`], a non-blocking,
//! non-async `std::sync::mpsc::SyncSender::try_send` -- never awaited,
//! never retried, silently a no-op if the queue is full or the consumer
//! thread is gone. Nothing about the consumer thread's behavior --
//! however long it blocks -- can ever occupy a Tokio worker, because it
//! is never scheduled by Tokio at all.
//!
//! This is deliberately not a logging framework: no levels, no
//! formatting pipeline, no destinations beyond stderr. Just a bounded
//! channel and a thread that drains it.

use std::time::Duration;

/// How many pending progress events may queue up before new ones are
/// silently dropped. Generous for a normal terminal (which drains in
/// microseconds), small enough that a permanently-stalled consumer can
/// never accumulate unbounded memory.
const DEFAULT_CAPACITY: usize = 64;

/// How long [`ProgressReporter::finish`] will wait for the consumer
/// thread to drain whatever was already queued, once the hot path has
/// already finished. Never called before dispatch -- only as a final,
/// best-effort flush so the last few summary lines aren't lost. Bounded
/// so a stalled consumer can never hang the caller either: past this
/// timeout, the join is simply abandoned (the OS thread is left to exit
/// on its own, whenever its current blocking write eventually returns).
const FINISH_TIMEOUT: Duration = Duration::from_millis(500);

/// A non-blocking emitter for cosmetic progress events of type `T`,
/// backed by a dedicated OS thread that owns the real rendering -- never
/// a Tokio task, never a Tokio worker thread.
pub struct ProgressReporter<T: Send + 'static> {
    tx: std::sync::mpsc::SyncSender<T>,
    handle: std::thread::JoinHandle<()>,
}

impl<T: Send + 'static> ProgressReporter<T> {
    /// Spawns the dedicated consumer OS thread. `render` is called once
    /// per event, in emission order, until every sender clone is dropped
    /// (i.e. this `ProgressReporter` and any handle derived from it).
    /// A panic inside `render` ends the consumer thread; subsequent
    /// `emit` calls simply become no-ops (a dead reporter is exactly as
    /// safe as a full one -- neither can affect the caller).
    pub fn spawn(render: impl FnMut(T) + Send + 'static) -> Self {
        Self::spawn_with_capacity(DEFAULT_CAPACITY, render)
    }

    pub fn spawn_with_capacity(
        capacity: usize,
        mut render: impl FnMut(T) + Send + 'static,
    ) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
        let handle = std::thread::spawn(move || {
            while let Ok(item) = rx.recv() {
                render(item);
            }
        });
        Self { tx, handle }
    }

    /// Non-blocking, best-effort emit -- `std::sync::mpsc::SyncSender::try_send`
    /// never blocks by contract, is not `async`, and is never retried on
    /// a full queue or a disconnected (dead-consumer-thread) channel.
    /// This is the *only* method the dispatch-critical path is ever
    /// allowed to call.
    pub fn emit(&self, item: T) {
        let _ = self.tx.try_send(item);
    }

    /// Best-effort final flush, only ever called *after* execution has
    /// already completed (never on the dispatch-critical path itself):
    /// drops this reporter's sender so the consumer thread's `recv()`
    /// loop ends once the queue drains, then sleeps a fixed
    /// [`FINISH_TIMEOUT`] to give it a chance to actually catch up.
    ///
    /// Deliberately **never calls `JoinHandle::join()`**, bounded or
    /// otherwise -- an earlier version of this method used
    /// `tokio::task::spawn_blocking` plus `tokio::time::timeout` to join
    /// the thread with a bound on the *awaiting* side, but that does not
    /// bound the *join itself*: the `spawn_blocking` task keeps trying to
    /// join the stalled thread even after the timeout elapses and this
    /// function has returned, and Tokio's default runtime shutdown waits
    /// for outstanding `spawn_blocking` tasks with no timeout of its own
    /// -- so a genuinely stuck consumer thread could still hang the
    /// *process's* eventual runtime teardown, even though `finish()`
    /// itself returned promptly. Sleeping instead of joining sidesteps
    /// that failure mode entirely: this function's own bound is the only
    /// bound that matters, the consumer thread is simply dropped
    /// (detached, never joined) afterward, and process exit is never
    /// blocked by however long that thread does or doesn't take to
    /// finish.
    pub async fn finish(self) {
        let Self { tx, handle } = self;
        drop(tx);
        tokio::time::sleep(FINISH_TIMEOUT).await;
        drop(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Item 4A: under a genuinely single-threaded Tokio runtime, a
    /// consumer that blocks for 2 seconds must never delay the producer
    /// -- this is exactly the scenario the previous Tokio-task-based
    /// design could not honestly satisfy without forcing a multi-thread
    /// runtime in the test. The consumer thread is not part of the Tokio
    /// runtime at all, so this now needs no special runtime flavor.
    #[tokio::test]
    async fn emit_never_blocks_even_when_the_consumer_stalls_for_two_seconds_on_a_single_thread_runtime()
     {
        let started_consuming = Arc::new(std::sync::Barrier::new(2));
        let started_consuming_for_render = started_consuming.clone();
        let reporter = ProgressReporter::spawn_with_capacity(4, move |_item: u32| {
            started_consuming_for_render.wait();
            std::thread::sleep(Duration::from_secs(2));
        });

        // Let the consumer thread actually pick up the first item and
        // start "stalling" before measuring emit()'s own latency.
        reporter.emit(1);
        started_consuming.wait();

        let started = std::time::Instant::now();
        reporter.emit(2);
        reporter.emit(3);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(100),
            "emit() must never block on a stalled consumer, even on a single-threaded Tokio \
             runtime, took {elapsed:?}"
        );
    }

    /// Item 4B: a consumer that permanently stops reading after the
    /// first event must not slow down producer completion.
    #[tokio::test]
    async fn a_consumer_that_stops_reading_after_the_first_event_never_slows_the_producer() {
        let reporter = ProgressReporter::spawn_with_capacity(1, |_item: u32| {
            // Reads (and discards) exactly one item, then blocks forever
            // -- simulates a consumer that has permanently stopped.
            std::thread::sleep(Duration::from_secs(2));
        });

        let started = std::time::Instant::now();
        for i in 0..500u32 {
            reporter.emit(i);
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(200),
            "500 emits against a consumer that stopped reading must all return immediately, \
             took {elapsed:?}"
        );
    }

    /// Item 4C: a full queue causes `try_send` to drop events, never to
    /// block.
    #[tokio::test]
    async fn a_full_queue_drops_events_without_blocking() {
        let reporter = ProgressReporter::spawn_with_capacity(1, |_item: u32| {
            std::thread::sleep(Duration::from_secs(2));
        });

        let started = std::time::Instant::now();
        for i in 0..100u32 {
            reporter.emit(i);
        }
        let elapsed = started.elapsed();

        assert!(elapsed < Duration::from_millis(100));
    }

    /// Item 4D: a panicking consumer thread never propagates into the
    /// producer, and the producer remains usable (silently a no-op)
    /// afterward.
    #[tokio::test]
    async fn a_panicking_consumer_never_affects_the_producer() {
        let reporter = ProgressReporter::spawn_with_capacity(4, |item: u32| {
            if item == 1 {
                panic!("simulated consumer panic");
            }
        });

        reporter.emit(1);
        // Give the consumer thread a moment to actually panic and exit.
        std::thread::sleep(Duration::from_millis(50));

        let started = std::time::Instant::now();
        reporter.emit(2);
        reporter.emit(3);
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(50));
    }

    /// Item 4E: `finish()` while the consumer is stalled must still
    /// return within (approximately) the documented bounded timeout,
    /// never hang waiting for the stalled thread.
    #[tokio::test]
    async fn finish_while_the_consumer_is_stalled_returns_within_the_bounded_timeout() {
        let reporter = ProgressReporter::spawn_with_capacity(4, |_item: u32| {
            std::thread::sleep(Duration::from_secs(2));
        });
        reporter.emit(1); // occupies the consumer thread indefinitely

        let started = std::time::Instant::now();
        reporter.finish().await;
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(700),
            "finish() must return within roughly FINISH_TIMEOUT even against a permanently \
             stalled consumer, took {elapsed:?}"
        );
    }

    /// Item 4F: under normal operation, emitted events are actually
    /// rendered.
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
    /// permanently stalled, and no consumer at all (thread already
    /// exited). No fragile microsecond gate: just a generous upper bound
    /// and a printed median/p90/p95 for a human to read, proving overhead
    /// stays negligible and independent of how fast anything downstream
    /// consumes.
    #[tokio::test]
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

        // Condition 2: consumer permanently stalled.
        let stalled = ProgressReporter::spawn_with_capacity(1, |_item: u32| {
            std::thread::sleep(Duration::from_secs(2));
        });
        stalled.emit(0); // occupies the consumer thread
        std::thread::sleep(Duration::from_millis(20)); // let it actually start
        let mut stalled_ns = Vec::with_capacity(SAMPLES);
        for i in 0..SAMPLES as u32 {
            let started = std::time::Instant::now();
            stalled.emit(i);
            stalled_ns.push(started.elapsed().as_nanos());
        }

        // Condition 3: no consumer at all (thread already exited).
        let disabled = ProgressReporter::spawn(|_item: u32| panic!("consumer exits immediately"));
        disabled.emit(0);
        std::thread::sleep(Duration::from_millis(20)); // let it actually exit
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

        for p95 in [d_p95, s_p95, x_p95] {
            assert!(
                p95 < 1_000_000,
                "emit() p95 overhead should be well under 1ms regardless of consumer state, \
                 got {p95}ns"
            );
        }
    }
}
