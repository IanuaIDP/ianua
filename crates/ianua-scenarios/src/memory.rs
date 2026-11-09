//! How much memory a scenario's platform holds, counted exactly.
//!
//! The platform runs in the scenario's own process, so one counting
//! allocator over the system's counts every byte the API, the worker and
//! every adapter take and give back, as well as the scenario's own. Each
//! nextest test is a process of its own, so a reading is that test's
//! alone.
//!
//! - [`reading`] says what is held now, the most held since the last
//!   [`reset_peak`], and how many allocations were made.
//! - [`Steady`] repeats a step and fails when what stays held grows with
//!   the rounds: a leak.
//! - The stack writes each test's [`MemoryReport`] when it stops, and
//!   refuses one whose peak passed its budget.

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The system allocator, counting what passes through it.
struct Counting;

/// Bytes held right now.
static HELD: AtomicUsize = AtomicUsize::new(0);

/// The most bytes held at once since the last [`reset_peak`].
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Allocations made since the process started.
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: Counting = Counting;

// SAFETY: every call is passed to the system allocator unchanged, with the
// same pointer and layout; the counters are atomics that never touch the
// memory handed out, so the allocator's guarantees are the system's.
// The crate denies unsafe code; an allocator cannot be written without it,
// and this is the one place the crate allows it.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `alloc`'s contract, passed on as it is.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            took(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `alloc_zeroed`'s contract, passed on.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            took(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` came from this allocator with `layout`, which the
        // caller guarantees, and this allocator's memory is the system's.
        unsafe { System.dealloc(pointer, layout) };
        HELD.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds `realloc`'s contract, passed on as it is.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            HELD.fetch_sub(layout.size(), Ordering::Relaxed);
            took(new_size);
        }
        moved
    }
}

/// Counts `size` bytes taken, raising the peak when it is passed.
fn took(size: usize) {
    let held = HELD.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(held, Ordering::Relaxed);
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
}

/// What the process holds, at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryReading {
    /// Bytes held now.
    pub held: usize,
    /// The most bytes held at once since the last [`reset_peak`].
    pub peak: usize,
    /// Allocations made since the process started.
    pub allocations: u64,
}

/// What the process holds now.
#[must_use]
pub(crate) fn reading() -> MemoryReading {
    MemoryReading {
        held: HELD.load(Ordering::Relaxed),
        peak: PEAK.load(Ordering::Relaxed),
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
    }
}

/// Starts counting the peak again from what is held now.
pub(crate) fn reset_peak() {
    PEAK.store(HELD.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// How many counted rounds pass between two progress lines in the log.
const PROGRESS_EVERY: usize = 10;

/// A step repeated to show that what it leaves held does not grow: a step
/// that leaks leaves a little more held each round.
#[derive(Debug, Clone, Copy)]
pub struct Steady {
    /// Rounds run first and not counted, so caches, pools and lazily made
    /// things settle before the measure starts.
    pub warm_up: usize,
    /// Rounds counted.
    pub rounds: usize,
    /// The most a round may leave held on average, in bytes: room for
    /// what grows legitimately, such as a log line buffered or a counter's
    /// key that lapses later.
    pub per_round: usize,
}

impl Steady {
    /// Runs `step` for the warm-up, then for the counted rounds, and
    /// answers what each counted round left held on average.
    ///
    /// # Panics
    ///
    /// When a counted round leaves more than [`Steady::per_round`] held on
    /// average, naming `what`, the growth and the readings.
    pub async fn holds<F, Fut>(self, what: &str, mut step: F) -> usize
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = ()>,
    {
        let started = std::time::Instant::now();
        for _ in 0..self.warm_up {
            step().await;
        }
        tracing::info!(what, warm_up = self.warm_up, took = ?started.elapsed(), "warmed up");
        let before = reading();
        for round in 1..=self.rounds {
            step().await;
            if round % PROGRESS_EVERY == 0 {
                tracing::info!(what, round, held = reading().held, took = ?started.elapsed(), "rounds done");
            }
        }
        let after = reading();
        let grown = after.held.saturating_sub(before.held);
        let per_round = grown / self.rounds.max(1);
        assert!(
            per_round <= self.per_round,
            "{what} leaves {per_round} bytes held per round over {} rounds \
             (at most {} allowed): {before:?} then {after:?}",
            self.rounds,
            self.per_round
        );
        per_round
    }
}

/// What a scenario's platform took, written when its stack stops.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct MemoryReport {
    /// The test, as nextest names it.
    pub test: String,
    /// The most bytes held at once while the stack ran, above what was held
    /// when it started.
    pub peak_above_start: usize,
    /// Bytes held after the stack stopped, above what was held when it
    /// started: what the stop did not give back.
    pub held_after_stop: usize,
    /// Allocations made while the stack ran.
    pub allocations: u64,
}

impl MemoryReport {
    /// The report of the test running now, from the reading at its start
    /// and the one after its stop.
    #[must_use]
    pub(crate) fn between(start: MemoryReading, end: MemoryReading) -> Self {
        Self {
            test: test_name(),
            peak_above_start: end.peak.saturating_sub(start.held),
            held_after_stop: end.held.saturating_sub(start.held),
            allocations: end.allocations.saturating_sub(start.allocations),
        }
    }

    /// Writes the report as JSON to `scenario-memory/<test>.json` in the
    /// workspace's build directory (`CARGO_TARGET_DIR`, or `target` at the
    /// workspace's root), so every run leaves one file per test to
    /// compare. A report that cannot be written is logged and dropped: it
    /// never fails the scenario it describes.
    pub(crate) fn write(&self) {
        let directory = std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(
                || std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
                std::path::PathBuf::from,
            )
            .join("scenario-memory");
        let file = directory.join(format!("{}.json", self.test.replace("::", ".")));
        let written = std::fs::create_dir_all(&directory).and_then(|()| {
            let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
            std::fs::write(&file, json)
        });
        if let Err(error) = written {
            tracing::warn!(%error, file = %file.display(), "the memory report was not written");
        }
    }
}

/// The test running now: nextest runs each test on a thread named after it.
fn test_name() -> String {
    std::thread::current()
        .name()
        .map_or_else(|| "unnamed".to_owned(), ToOwned::to_owned)
}
