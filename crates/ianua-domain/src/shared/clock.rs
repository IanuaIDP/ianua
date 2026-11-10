//! Time source for the domain.
//!
//! Aggregates read the current time through [`now`], never through
//! `OffsetDateTime::now_utc()`. Tests can then fix the time. In production
//! [`now`] is `OffsetDateTime::now_utc()`. Under `test` or `test-support`, a
//! test can fix the time for its own thread with `freeze`, or install a
//! forward-moving offset through `stepping` on a single runtime thread.

use time::OffsetDateTime;

#[cfg(any(test, feature = "test-support"))]
// Only test support can move this clock; an unrepresentable test instant
// must stop that test, as invalid fixtures in test_support do.
#[allow(clippy::expect_used)]
pub mod stepping;

/// The current UTC time.
///
/// Under `test` or `test-support`, this is the time `freeze` set for the
/// current thread, if one is set. Otherwise it is the wall clock plus any
/// test-only stepped offset installed on this thread.
#[must_use]
// The one place the domain reads the wall clock; everything else calls this.
#[allow(clippy::disallowed_methods)]
pub fn now() -> OffsetDateTime {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(frozen) = test_clock::get() {
        return frozen;
    }
    let wall = OffsetDateTime::now_utc();
    #[cfg(any(test, feature = "test-support"))]
    let wall = stepping::shifted(wall);
    to_the_microsecond(wall)
}

/// `at` without what lies below a microsecond, the finest time the database
/// keeps. Linux clocks read nanoseconds, so a time still held in memory or in
/// a stored document would otherwise fall just after its own stored copy.
fn to_the_microsecond(at: OffsetDateTime) -> OffsetDateTime {
    let below_a_microsecond = i64::from(at.nanosecond() % 1_000);
    at.checked_sub(time::Duration::nanoseconds(below_a_microsecond))
        .unwrap_or(at)
}

/// How long passed from `earlier` to `later`.
///
/// It is negative when `later` is the earlier of the two. This is the one
/// place the domain subtracts two instants. It cannot overflow. The widest
/// gap two instants can have is about twenty thousand years, far inside what
/// a [`Duration`](time::Duration) holds.
#[must_use]
#[allow(clippy::arithmetic_side_effects)]
pub fn between(earlier: OffsetDateTime, later: OffsetDateTime) -> time::Duration {
    later - earlier
}

/// Fixes [`now`] at `instant` for the current thread until the returned guard
/// is dropped.
///
/// Only for tests.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn freeze(instant: OffsetDateTime) -> FrozenClock {
    test_clock::set(Some(instant));
    FrozenClock(())
}

/// Reaches at least `instant` on an installed test clock, retaining its fixed
/// or wall-ticking behavior. Past instants never rewind it. Returns false
/// without changing time when this thread has not opted into a test clock.
///
/// # Panics
///
/// When advancing a stepped clock would overflow its offset.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn reach(instant: OffsetDateTime) -> bool {
    let Some(current) = test_clock::get() else {
        return stepping::advance_to(instant);
    };
    test_clock::set(Some(current.max(instant)));
    true
}

/// Restores the real clock when dropped.
#[cfg(any(test, feature = "test-support"))]
pub struct FrozenClock(());

#[cfg(any(test, feature = "test-support"))]
impl Drop for FrozenClock {
    /// Removes the frozen instant so this thread reads its ordinary clock.
    fn drop(&mut self) {
        test_clock::set(None);
    }
}

#[cfg(any(test, feature = "test-support"))]
impl FrozenClock {
    /// Advances the installed frozen instant while keeping subsequent reads
    /// fixed there, so boundary tests do not also advance with wall time.
    ///
    /// # Panics
    ///
    /// When no frozen clock is installed on this thread or `instant` is earlier
    /// than its current instant.
    pub fn advance_to(&self, instant: OffsetDateTime) {
        assert!(
            test_clock::get().is_some_and(|current| instant >= current),
            "a frozen clock only moves forward on its owning thread"
        );
        test_clock::set(Some(instant));
    }
}

#[cfg(any(test, feature = "test-support"))]
mod test_clock {
    use std::cell::Cell;

    use time::OffsetDateTime;

    thread_local! {
        static FROZEN: Cell<Option<OffsetDateTime>> = const { Cell::new(None) };
    }

    /// The frozen instant installed on this thread, if any.
    pub(super) fn get() -> Option<OffsetDateTime> {
        FROZEN.with(Cell::get)
    }

    /// Installs a frozen instant or restores the thread's ordinary clock.
    pub(super) fn set(value: Option<OffsetDateTime>) {
        FROZEN.with(|c| c.set(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compares the domain clock with the wall clock it reads.
    /// With no frozen time set, [`now`] falls between two wall clock reads
    /// taken just before and just after it.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn now_tracks_wall_clock_by_default() {
        let before = to_the_microsecond(OffsetDateTime::now_utc());
        let n = now();
        let after = OffsetDateTime::now_utc();
        assert!(n >= before && n <= after);
    }

    /// A time read to the nanosecond loses what the database could not keep,
    /// so it equals its stored copy.
    #[test]
    fn a_time_is_cut_to_the_microsecond_the_store_keeps() {
        let exact = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789).unwrap();

        let kept = to_the_microsecond(exact);

        assert_eq!(kept.unix_timestamp_nanos(), 1_700_000_000_123_456_000);
    }

    /// The clock itself never answers finer than a microsecond.
    #[test]
    fn now_is_told_to_the_microsecond() {
        assert_eq!(now().nanosecond() % 1_000, 0);
    }

    /// A test freezes the clock at a fixed instant. Every read returns that
    /// instant until the guard drops, and then the real time comes back.
    #[test]
    fn freeze_pins_time_until_dropped() {
        let fixed = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        {
            let _g = freeze(fixed);
            assert_eq!(now(), fixed);
            assert_eq!(now(), fixed);
        }
        assert_ne!(now(), fixed);
    }

    /// The frozen clock advances to an exact instant and stays there until
    /// explicitly advanced again. Dropping it restores ordinary clock reads.
    #[test]
    fn a_frozen_instant_can_advance_without_reintroducing_wall_time() {
        let fixed = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let later = fixed + time::Duration::seconds(1);
        {
            let guard = freeze(fixed);
            guard.advance_to(later);
            assert_eq!(now(), later);
            guard.advance_to(later);
            assert_eq!(now(), later);
        }
        assert_ne!(now(), later);
    }

    /// Moving a frozen clock back one second panics with the forward-only
    /// constraint instead of silently accepting the test's rewind.
    #[test]
    #[should_panic(expected = "a frozen clock only moves forward")]
    fn a_frozen_clock_cannot_move_backwards() {
        let fixed = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let guard = freeze(fixed);
        guard.advance_to(fixed - time::Duration::seconds(1));
    }

    /// An authenticator can request its next step on the installed fixed
    /// clock. Asking for an older step leaves the chosen instant unchanged.
    #[test]
    fn reaching_a_step_preserves_a_fixed_clocks_forward_only_behavior() {
        let fixed = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let later = fixed + time::Duration::seconds(30);
        {
            let _guard = freeze(fixed);
            assert!(reach(later));
            assert_eq!(now(), later);
            assert!(reach(fixed));
            assert_eq!(now(), later);
        }
        assert!(!reach(later));
    }
}
