//! Locking one origin out of one account after too many failed sign-ins.
//!
//! Failures are counted per account and origin together: the address the
//! sign-in names, and the network the attempt came from (see
//! [`AttemptOrigin`](crate::domains::authentication::risk_engine::origin::AttemptOrigin)).
//! Mallory guessing Ann's password from her own network locks that network
//! out of Ann's account, and nothing else: Ann, from anywhere else, still
//! signs in with her password. Guessing spread over many networks is slowed
//! account-wide instead, never locked, by
//! [`AccountPace`](crate::domains::authentication::risk_engine::pace::AccountPace).
//! Once it comes from many networks, the account is under attack, and a
//! right password from a new device must prove more, as
//! [`AccountAttack`](crate::domains::authentication::risk_engine::attack::AccountAttack)
//! says.
//!
//! The counts live outside the domain, on state every node shares, so two
//! guesses at once both count. The rules here are pure functions of those
//! counts.
//!
//! Infrastructure rate limits, by IP in nginx or Cloudflare, protect the
//! network. These limits protect the sign-in rules. They know about users,
//! tenants and the sign-in itself.

use std::cmp::Ordering;
use std::num::NonZeroU32;

use time::OffsetDateTime;

use crate::types::Lifetime;

/// When failed sign-ins from one origin lock it out of one account, and for
/// how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicy {
    /// Failed attempts that lock the origin out.
    max_failed_attempts: NonZeroU32,
    /// How long a lockout lasts.
    lockout: Lifetime,
    /// How long failed attempts are counted for, from the first failure. The
    /// window is fixed, not sliding.
    window: Lifetime,
}

impl RateLimitPolicy {
    /// The default for most tenants. 5 failed attempts in 15 minutes lock the
    /// origin out for 30 minutes.
    ///
    /// It is built at compile time, so the `unwrap`s cannot fail at run time.
    /// A zero here would not compile.
    pub const DEFAULT: Self = Self::new(
        NonZeroU32::new(5).unwrap(),
        Lifetime::from_secs(NonZeroU32::new(1800).unwrap()),
        Lifetime::from_secs(NonZeroU32::new(900).unwrap()),
    );

    /// A strict policy for high-security tenants. 3 failed attempts in 5
    /// minutes lock the origin out for an hour.
    ///
    /// It is built at compile time, so the `unwrap`s cannot fail at run time.
    /// A zero here would not compile.
    pub const STRICT: Self = Self::new(
        NonZeroU32::new(3).unwrap(),
        Lifetime::from_secs(NonZeroU32::new(3600).unwrap()),
        Lifetime::from_secs(NonZeroU32::new(300).unwrap()),
    );

    /// A policy locking after `max_failed_attempts` failures within `window`,
    /// for `lockout`.
    #[must_use]
    pub const fn new(max_failed_attempts: NonZeroU32, lockout: Lifetime, window: Lifetime) -> Self {
        Self {
            max_failed_attempts,
            lockout,
            window,
        }
    }

    /// Failed attempts that lock the origin out.
    #[must_use]
    pub fn max_failed_attempts(&self) -> u32 {
        self.max_failed_attempts.get()
    }

    /// How long a lockout lasts.
    #[must_use]
    pub fn lockout(&self) -> Lifetime {
        self.lockout
    }

    /// How long failures are counted for, from the first one.
    #[must_use]
    pub fn window(&self) -> Lifetime {
        self.window
    }

    /// What it means that `failures` failures from one origin against one
    /// account are now counted in the window, the latest at `now`.
    ///
    /// The failure that reaches the limit locks the origin out until the
    /// lockout has passed. A count past the limit means two failures raced
    /// past it, or the lock was not kept: it locks again, so a lock that
    /// failed to stick never leaves the origin open.
    #[must_use]
    pub fn after_failures(&self, failures: u32, now: OffsetDateTime) -> AttemptOutcome {
        let max = self.max_failed_attempts();
        let until = now.saturating_add(self.lockout.duration());
        match failures.cmp(&max) {
            Ordering::Less => AttemptOutcome::Allowed {
                remaining: max.saturating_sub(failures),
            },
            Ordering::Equal => AttemptOutcome::LockedOut(OriginLockout {
                failed_attempts: failures,
                until,
            }),
            Ordering::Greater => AttemptOutcome::PastTheLimit { until },
        }
    }
}

/// Whether an origin is locked out of an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lockout {
    /// Not locked.
    Open,
    /// Locked until this instant.
    Until(OffsetDateTime),
}

/// What one attempt did to its origin's count of failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptTally {
    /// Nothing: the attempt was refused before its password counted, or
    /// was never decided.
    Untouched,
    /// A failure to count.
    Failed,
    /// A right password: the origin's count starts again.
    Cleared,
}

/// One attempt at an account from one origin: whether the origin was locked
/// out when the attempt began, and what the attempt did.
///
/// The application reads the origin's lockout before the attempt, the
/// domain's sign-in rules ask [`is_locked`](Self::is_locked) and mark a
/// wrong password with [`record_failure`](Self::record_failure) or a right
/// one with [`reset`](Self::reset), and the application then counts or
/// clears as the [`tally`](Self::tally) says. The tracker never counts
/// itself: two guesses at once must both count, so the counting happens
/// in one step on the shared state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginAttemptTracker {
    lockout: Lockout,
    tally: AttemptTally,
}

impl LoginAttemptTracker {
    /// An attempt from an origin that is not locked out.
    #[must_use]
    pub fn new() -> Self {
        Self::standing(Lockout::Open)
    }

    /// An attempt from an origin standing at `lockout` when it began.
    #[must_use]
    pub fn standing(lockout: Lockout) -> Self {
        Self {
            lockout,
            tally: AttemptTally::Untouched,
        }
    }

    /// Whether the origin was locked out when the attempt began, and until
    /// when.
    #[must_use]
    pub fn lockout(&self) -> Lockout {
        self.lockout
    }

    /// When the origin's lockout ends, if it is locked out.
    #[must_use]
    pub fn locked_until(&self) -> Option<OffsetDateTime> {
        let Lockout::Until(until) = self.lockout else {
            return None;
        };
        Some(until)
    }

    /// Whether the origin is locked out at `now`.
    #[must_use]
    pub fn is_locked(&self, now: OffsetDateTime) -> bool {
        self.locked_until().is_some_and(|until| now < until)
    }

    /// Marks the attempt as a failure to count against its origin.
    pub fn record_failure(&mut self) {
        self.tally = AttemptTally::Failed;
    }

    /// Marks the attempt as a right password, which starts the origin's
    /// count again.
    pub fn reset(&mut self) {
        self.tally = AttemptTally::Cleared;
    }

    /// What the attempt did to its origin's count.
    #[must_use]
    pub fn tally(&self) -> AttemptTally {
        self.tally
    }
}

impl Default for LoginAttemptTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// What a counted failure means for its origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The origin can still try.
    Allowed {
        /// Attempts left before lockout.
        remaining: u32,
    },
    /// This failure reached the limit and locks the origin out.
    LockedOut(OriginLockout),
    /// An earlier failure reached the limit. The origin is locked out
    /// again, with no new record: the failure that reached it made one.
    PastTheLimit {
        /// When the lockout expires.
        until: OffsetDateTime,
    },
}

impl AttemptOutcome {
    /// Whether the origin can proceed with another attempt.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// When the origin is locked out until, once this failure is counted,
    /// or `None` while it may still try.
    #[must_use]
    pub fn locked_until(&self) -> Option<OffsetDateTime> {
        match self {
            Self::Allowed { .. } => None,
            Self::LockedOut(lockout) => Some(lockout.until),
            Self::PastTheLimit { until } => Some(*until),
        }
    }
}

/// The lockout a failure set by reaching the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginLockout {
    failed_attempts: u32,
    until: OffsetDateTime,
}

impl OriginLockout {
    /// The failures counted from the origin when it was locked out.
    #[must_use]
    pub fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    /// When the lockout ends.
    #[must_use]
    pub fn until(&self) -> OffsetDateTime {
        self.until
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::NonZeroU32;

    use proptest::prelude::*;
    use time::Duration;

    use super::*;
    use crate::domains::authentication::risk_engine::origin::AttemptOrigin;

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn rules(attempts: u32, lockout_secs: i64, window_secs: i64) -> RateLimitPolicy {
        RateLimitPolicy::new(
            NonZeroU32::new(attempts).unwrap(),
            Lifetime::seconds(lockout_secs).unwrap(),
            Lifetime::seconds(window_secs).unwrap(),
        )
    }

    fn policy() -> RateLimitPolicy {
        rules(3, 600, 300)
    }

    /// The default policy locks after 5 failures in 15 minutes, for 30
    /// minutes.
    #[test]
    fn default_policy_values() {
        let p = RateLimitPolicy::DEFAULT;
        assert_eq!(p.max_failed_attempts(), 5);
        assert_eq!(p.lockout().whole_seconds(), 1800);
        assert_eq!(p.window().whole_seconds(), 900);
    }

    /// The strict policy locks after 3 failures, for an hour.
    #[test]
    fn strict_policy_values() {
        let p = RateLimitPolicy::STRICT;
        assert_eq!(p.max_failed_attempts(), 3);
        assert_eq!(p.lockout().whole_seconds(), 3600);
    }

    /// Under a limit of 3, Mallory's first and second wrong passwords from
    /// her network leave her 2 and 1 tries.
    #[test]
    fn failures_below_the_limit_are_allowed() {
        let t = now();

        assert_eq!(
            policy().after_failures(1, t),
            AttemptOutcome::Allowed { remaining: 2 }
        );
        assert_eq!(
            policy().after_failures(2, t),
            AttemptOutcome::Allowed { remaining: 1 }
        );
    }

    /// Under a limit of 3 and a 10 minute lockout, the third wrong password
    /// locks Mallory's network out for exactly 10 minutes from it.
    #[test]
    fn the_failure_at_the_limit_locks_the_origin_out() {
        let t = now();

        let outcome = policy().after_failures(3, t);

        let AttemptOutcome::LockedOut(lockout) = outcome else {
            panic!("the third failure reaches the limit: {outcome:?}");
        };
        assert_eq!(lockout.until(), t + Duration::seconds(600));
        assert_eq!(lockout.failed_attempts(), 3);
        assert!(!outcome.is_allowed());
    }

    /// A failure count above the threshold still produces the configured lockout deadline.
    #[test]
    fn a_count_past_the_limit_locks_again_without_a_new_record() {
        let t = now();

        let outcome = policy().after_failures(4, t);

        assert_eq!(
            outcome,
            AttemptOutcome::PastTheLimit {
                until: t + Duration::seconds(600)
            }
        );
        assert_eq!(outcome.locked_until(), Some(t + Duration::seconds(600)));
    }

    /// A tracker read open is not locked, and one read locked until a
    /// moment holds until its last second and not beyond.
    #[test]
    fn a_lockout_holds_until_its_last_second_and_not_beyond() {
        let t = now();
        let open = LoginAttemptTracker::new();
        let locked = LoginAttemptTracker::standing(Lockout::Until(t + Duration::seconds(600)));

        assert!(!open.is_locked(t));
        assert!(locked.is_locked(t + Duration::seconds(599)));
        assert!(!locked.is_locked(t + Duration::seconds(600)));
        assert_eq!(locked.locked_until(), Some(t + Duration::seconds(600)));
    }

    /// An attempt starts untouched; a wrong password marks it a failure, a
    /// right one clears the origin's count.
    #[test]
    fn the_tally_says_what_the_attempt_did() {
        let mut failed = LoginAttemptTracker::new();
        let mut cleared = LoginAttemptTracker::new();

        assert_eq!(failed.tally(), AttemptTally::Untouched);
        failed.record_failure();
        cleared.reset();

        assert_eq!(failed.tally(), AttemptTally::Failed);
        assert_eq!(cleared.tally(), AttemptTally::Cleared);
    }

    /// Ann's password is right, then her sign-in is refused for its risk.
    /// The refusal is what counts: the attempt is a failure.
    #[test]
    fn a_failure_after_a_right_password_counts() {
        let mut tracker = LoginAttemptTracker::new();

        tracker.reset();
        tracker.record_failure();

        assert_eq!(tracker.tally(), AttemptTally::Failed);
    }

    proptest! {
        /// Whatever the limit and the count, exactly the failure at the
        /// limit makes the lockout record, every count from it on is locked
        /// out, and below it the tries left add up to the limit.
        #[test]
        fn the_limit_alone_decides_the_lockout(max in 1u32..200, failures in 1u32..400) {
            let policy = rules(max, 60, 600);
            let t = now();

            let outcome = policy.after_failures(failures, t);

            prop_assert_eq!(
                matches!(outcome, AttemptOutcome::LockedOut(_)),
                failures == max
            );
            prop_assert_eq!(outcome.locked_until().is_some(), failures >= max);
            if let AttemptOutcome::Allowed { remaining } = outcome {
                prop_assert_eq!(remaining.saturating_add(failures), max);
            }
        }

        /// Whatever Mallory guesses from her address, Ann's address is
        /// locked out of the account only by Ann's own failures: each
        /// origin's failures are counted under its own key and only its own
        /// count reaches its limit.
        #[test]
        fn guessing_from_one_origin_never_locks_another(
            mallory in any::<u32>(),
            ann in any::<u32>(),
            guesses in 0u32..60,
            ann_failures in 0u32..10,
            max in 1u32..10,
        ) {
            let origin = |bits: u32| {
                let ip = crate::types::IpAddress::new(std::net::Ipv4Addr::from(bits).to_string())
                    .unwrap();
                AttemptOrigin::of(crate::types::Fact::Known(&ip))
            };
            prop_assume!(origin(mallory) != origin(ann));
            let policy = rules(max, 600, 900);
            let t = now();
            let mut counts: HashMap<AttemptOrigin, u32> = HashMap::new();
            let mut locked: HashMap<AttemptOrigin, OffsetDateTime> = HashMap::new();
            let attempts = std::iter::repeat_n(origin(mallory), guesses as usize)
                .chain(std::iter::repeat_n(origin(ann), ann_failures as usize));

            for from in attempts {
                let count = counts.entry(from).or_default();
                *count = count.saturating_add(1);
                if let Some(until) = policy.after_failures(*count, t).locked_until() {
                    locked.insert(from, until);
                }
            }

            prop_assert_eq!(locked.contains_key(&origin(ann)), ann_failures >= max);
            prop_assert_eq!(locked.contains_key(&origin(mallory)), guesses >= max);
        }
    }
}
