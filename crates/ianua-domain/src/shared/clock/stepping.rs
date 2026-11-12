//! An opt-in clock for tests that need several instants without waiting.
//!
//! Time keeps ticking, with a forward offset confined to this thread.
//! It does not move Tokio's timers or an external service's clock. A
//! current-thread runtime keeps its application tasks on this same clock;
//! a runtime whose tasks move between threads must not use it.

use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;

use time::{Duration, OffsetDateTime};

use crate::shared::clock::{self, test_clock};

thread_local! {
    static OFFSET: Cell<Option<Duration>> = const { Cell::new(None) };
}

/// Keeps this thread's advancing clock installed until dropped. The
/// guard cannot leave its thread, and only one may be installed at once.
pub struct SteppedClock {
    thread: PhantomData<Rc<()>>,
}

impl SteppedClock {
    /// Starts at the wall clock, allowing subsequent forward steps while
    /// real time continues to pass between them.
    ///
    /// # Panics
    ///
    /// When this thread already has a frozen or stepped clock.
    #[must_use]
    pub fn start() -> Self {
        assert!(test_clock::get().is_none(), "the clock is frozen");
        OFFSET.with(|offset| {
            assert!(offset.get().is_none(), "the clock is already stepped");
            offset.set(Some(Duration::ZERO));
        });
        Self {
            thread: PhantomData,
        }
    }

    /// Starts one when this thread has no test clock yet, or `None` when a
    /// frozen or stepped clock is already installed and stays in charge.
    #[must_use]
    pub fn unless_installed() -> Option<Self> {
        let installed = test_clock::get().is_some() || OFFSET.with(|offset| offset.get().is_some());
        match installed {
            true => None,
            false => Some(Self::start()),
        }
    }
}

impl Drop for SteppedClock {
    /// Restores this thread's wall clock even when the test unwinds.
    fn drop(&mut self) {
        OFFSET.with(|offset| offset.set(None));
    }
}

/// Moves an installed clock forward to at least `instant`. A past instant
/// never turns it back. Returns false without changing anything when no
/// stepped clock is installed, so fixtures can retain their real waits.
///
/// # Panics
///
/// When a frozen clock masks the stepped clock, or the offset overflows.
#[must_use]
pub fn advance_to(instant: OffsetDateTime) -> bool {
    OFFSET.with(|offset| {
        let Some(held) = offset.get() else {
            return false;
        };
        assert!(test_clock::get().is_none(), "the clock is frozen");
        let gap = clock::between(clock::now(), instant);
        if gap.is_positive() {
            offset.set(Some(
                held.checked_add(gap).expect("a representable test offset"),
            ));
        }
        true
    })
}

/// Adds the installed offset to a wall-clock read, or leaves it unchanged
/// when the thread has no stepped clock.
///
/// # Panics
///
/// When the test moved time beyond the representable date range.
pub(super) fn shifted(wall: OffsetDateTime) -> OffsetDateTime {
    OFFSET.with(|offset| {
        wall.checked_add(offset.get().unwrap_or(Duration::ZERO))
            .expect("a representable test instant")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A step is visible through the ordinary domain clock, cannot run
    /// backwards and disappears when its guard leaves scope.
    #[test]
    fn steps_are_forward_and_scoped() {
        let before = crate::shared::clock::now();
        let future = before + Duration::hours(1);
        {
            let _clock = SteppedClock::start();
            assert!(advance_to(future));
            assert!(crate::shared::clock::now() >= future);
            assert!(advance_to(before));
            assert!(crate::shared::clock::now() >= future);
        }
        assert!(crate::shared::clock::now() < future);
        assert!(!advance_to(future));
    }

    /// Advancing this thread by an hour leaves another thread before that
    /// instant, and that thread cannot advance a clock it never installed.
    #[test]
    fn a_step_never_reaches_another_thread() {
        let _clock = SteppedClock::start();
        let future = crate::shared::clock::now() + Duration::hours(1);
        assert!(advance_to(future));
        std::thread::spawn(move || {
            assert!(crate::shared::clock::now() < future);
            assert!(!advance_to(future));
        })
        .join()
        .unwrap();
    }

    /// A clock the test already installed stays in charge, and a thread
    /// with none gets a stepped one.
    #[test]
    fn a_clock_already_installed_is_left_in_charge() {
        let held = SteppedClock::start();
        assert!(SteppedClock::unless_installed().is_none());
        drop(held);
        let frozen = crate::shared::clock::freeze(crate::shared::clock::now());
        assert!(SteppedClock::unless_installed().is_none());
        drop(frozen);
        let fresh = SteppedClock::unless_installed();
        assert!(fresh.is_some());
        assert!(advance_to(crate::shared::clock::now() + Duration::hours(1)));
    }

    /// A panic cannot leave the next test using a previous test's offset.
    #[test]
    fn unwinding_restores_the_wall_clock() {
        let future = crate::shared::clock::now() + Duration::hours(1);
        let result = std::panic::catch_unwind(|| {
            let _clock = SteppedClock::start();
            assert!(advance_to(future));
            panic!("the scenario failed");
        });
        assert!(result.is_err());
        assert!(crate::shared::clock::now() < future);
        assert!(!advance_to(future));
    }
}
