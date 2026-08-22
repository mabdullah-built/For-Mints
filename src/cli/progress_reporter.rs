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
}
