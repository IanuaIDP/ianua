//! Optional control of application time for cryptographic scenarios.
//!
//! The platform, gateway and authenticator share the domain clock on a
//! current-thread runtime. Advancing it changes the time the real checks
//! see, never their tolerance, period or replay rules. External cache
//! expiry and runtime timers remain real and must be tested with real waits.

use std::time::Duration;

use ianua_infra::test_support::clock::{self, stepping};
use time::OffsetDateTime;
use tokio::runtime::{Handle, RuntimeFlavor};

/// An opt-in clock for a current-thread scenario, kept through stack shutdown.
/// Application checks outside its scope use the ordinary wall clock.
pub struct Clock {
    scope: Scope,
}

/// The time behavior held by one current-thread scenario.
enum Scope {
    /// Wall time continues to pass between explicit forward steps.
    Stepped { _guard: stepping::SteppedClock },
    /// Every application read sees the exact last chosen instant.
    Fixed(clock::FrozenClock),
}

impl Clock {
    /// Lets this scenario advance application time on its current thread.
    /// Create it before starting the stack and drop it after stopping it.
    ///
    /// # Panics
    ///
    /// When no runtime is entered, tasks could move between runtime
    /// threads, or another test clock is already installed.
    #[must_use]
    pub fn controlled() -> Self {
        assert_eq!(
            Handle::current().runtime_flavor(),
            RuntimeFlavor::CurrentThread,
            "a controlled clock requires a current-thread runtime"
        );
        Self {
            scope: Scope::Stepped {
                _guard: stepping::SteppedClock::start(),
            },
        }
    }

    /// Pins application time at the next whole second until explicitly advanced,
    /// including in spawned tasks, so database precision cannot shift boundaries.
    /// Runtime timers and external services continue to use real time.
    ///
    /// # Panics
    ///
    /// When no runtime is entered, tasks can move between threads, or the
    /// next whole second is outside the clock's representable range.
    /// A scenario must fail if its chosen instant cannot be represented.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn fixed() -> Self {
        assert_eq!(
            Handle::current().runtime_flavor(),
            RuntimeFlavor::CurrentThread,
            "a fixed clock requires a current-thread runtime"
        );
        let instant = clock::now()
            .checked_add(time::Duration::seconds(1))
            .expect("the next second is representable")
            .replace_nanosecond(0)
            .expect("zero nanoseconds is a valid fraction");
        Self {
            scope: Scope::Fixed(clock::freeze(instant)),
        }
    }

    /// Advances the application clock by `duration`; real signature and
    /// expiry checks then run at the later instant.
    ///
    /// # Panics
    ///
    /// When the duration or resulting instant is outside the clock's range.
    /// Rejecting an impossible test instant must abort the scenario.
    #[allow(clippy::expect_used)]
    pub fn advance(&self, duration: Duration) {
        let duration = time::Duration::try_from(duration).expect("a representable duration");
        let later = clock::now()
            .checked_add(duration)
            .expect("a representable instant");
        match &self.scope {
            Scope::Stepped { .. } => {
                assert!(stepping::advance_to(later), "the scenario holds its clock");
            }
            Scope::Fixed(guard) => guard.advance_to(later),
        }
    }
}

/// The seconds the application and this thread's authenticator see now.
///
/// # Panics
///
/// When the clock is before the Unix epoch.
/// Authenticator fixtures require a post-epoch clock and assert that setup.
#[allow(clippy::expect_used)]
pub(crate) fn seconds() -> u64 {
    clock::now()
        .unix_timestamp()
        .try_into()
        .expect("a clock after the Unix epoch")
}

/// Advances an opted-in scenario to the next unused authenticator step.
/// Without a controlled clock, the caller still waits for real time.
///
/// # Panics
///
/// When the requested step is outside the representable clock range.
/// An unrepresentable authenticator step is a failed scenario prerequisite.
#[allow(clippy::expect_used)]
pub(crate) fn reach_step(step: u64, period: u64) {
    let seconds = step.checked_mul(period).expect("a representable time step");
    let seconds = i64::try_from(seconds).expect("a representable timestamp");
    let instant = OffsetDateTime::from_unix_timestamp(seconds).expect("a valid instant");
    let _controlled = clock::reach(instant);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same clock reaches tasks spawned as the platform's listeners
    /// are spawned, and is restored after the scenario leaves scope.
    #[tokio::test]
    async fn spawned_tasks_read_the_advanced_clock() {
        let before = seconds();
        {
            let clock = Clock::controlled();
            clock.advance(Duration::from_secs(3600));
            let observed = tokio::spawn(async { seconds() })
                .await
                .expect("the task finishes");
            assert!(observed >= before + 3600);
        }
        assert!(seconds() < before + 3600);
    }

    /// Exact time is shared with spawned listeners and does not drift while
    /// runtime timers tick. Explicit advancement changes the instant once.
    #[tokio::test]
    async fn a_fixed_clock_stays_exact_while_runtime_timers_continue() {
        let clock = Clock::fixed();
        let before = clock::now();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(clock::now(), before);
        clock.advance(Duration::from_secs(1));
        let observed = tokio::spawn(async { clock::now() }).await.unwrap();
        assert_eq!(observed, before + time::Duration::seconds(1));
    }

    /// A runtime that can move tasks between threads refuses the controlled
    /// clock, whose time is local to one thread.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[should_panic(expected = "a controlled clock requires a current-thread runtime")]
    async fn a_runtime_that_moves_tasks_is_refused() {
        let _clock = Clock::controlled();
    }
}
