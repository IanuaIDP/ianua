//! Each tenant's session timeouts.
//!
//! Two timeouts run side by side:
//! - **Absolute timeout**: the session ends a set time after it starts,
//!   whatever it does.
//! - **Idle timeout**: the session ends after a set time without use.
//!
//! The session ends at whichever comes first.

use std::num::NonZeroU32;

use time::OffsetDateTime;

use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Lifetime;

/// How long a session may go unused before it ends, or that it never idles
/// out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleTimeout {
    /// It never idles out. Only the absolute lifetime ends it.
    Never,
    /// It ends after going unused this long.
    After(Lifetime),
}

/// One tenant's session timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTimeoutPolicy {
    /// How long a session lasts from its creation, whatever it does.
    absolute: Lifetime,
    /// How long a session may go unused, or that it never idles out.
    idle: IdleTimeout,
}

impl SessionTimeoutPolicy {
    /// A standard policy for most tenants. Sessions last 24 hours and idle
    /// out after 30 minutes.
    ///
    /// It is built at compile time, so the `unwrap`s cannot fail at run time.
    /// A zero here would not compile.
    pub const STANDARD: Self = Self {
        absolute: Lifetime::from_secs(NonZeroU32::new(86_400).unwrap()),
        idle: IdleTimeout::After(Lifetime::from_secs(NonZeroU32::new(1800).unwrap())),
    };

    /// A strict policy for high-security tenants. Sessions last 8 hours and
    /// idle out after 15 minutes.
    ///
    /// It is built at compile time, so the `unwrap`s cannot fail at run time.
    /// A zero here would not compile.
    pub const STRICT: Self = Self {
        absolute: Lifetime::from_secs(NonZeroU32::new(28_800).unwrap()),
        idle: IdleTimeout::After(Lifetime::from_secs(NonZeroU32::new(900).unwrap())),
    };

    /// A relaxed policy for low-risk tenants. Sessions last 7 days and never
    /// idle out.
    ///
    /// It is built at compile time, so the `unwrap`s cannot fail at run time.
    /// A zero here would not compile.
    pub const RELAXED: Self = Self {
        absolute: Lifetime::from_secs(NonZeroU32::new(604_800).unwrap()),
        idle: IdleTimeout::Never,
    };

    /// A policy ending sessions `absolute` after they start, and after
    /// `idle` without use unless it never idles out.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `idle` is longer than `absolute`.
    ///   The session would always end before it could go idle.
    pub fn new(absolute: Lifetime, idle: IdleTimeout) -> Result<Self, DomainError> {
        if let IdleTimeout::After(idle) = idle
            && idle > absolute
        {
            return Err(DomainError::invalid(message!(
                "authentication-an-idle-timeout-cannot-outlast-the",
                format!("an idle timeout cannot outlast the {absolute} session it belongs to")
            )));
        }
        Ok(Self { absolute, idle })
    }

    /// How long a session lasts from its creation.
    #[must_use]
    pub fn absolute(&self) -> Lifetime {
        self.absolute
    }

    /// How long a session may go unused, or that it never idles out.
    #[must_use]
    pub fn idle(&self) -> IdleTimeout {
        self.idle
    }

    /// When a session created at `created_at` reaches its absolute timeout.
    #[must_use]
    pub fn absolute_expiry(&self, created_at: OffsetDateTime) -> OffsetDateTime {
        self.absolute.ends_after(created_at)
    }

    /// Whether a session last used at `last_active_at` has gone idle by
    /// `now`. Never, when the policy has no idle timeout.
    #[must_use]
    pub fn is_idle(&self, last_active_at: OffsetDateTime, now: OffsetDateTime) -> bool {
        match self.idle {
            IdleTimeout::Never => false,
            IdleTimeout::After(idle) => now >= idle.ends_after(last_active_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn lifetime(secs: i64) -> Lifetime {
        Lifetime::seconds(secs).unwrap()
    }

    /// A tenant sets a 600 second session with a 601 second idle timeout.
    /// The policy is refused.
    #[test]
    fn an_idle_timeout_longer_than_the_session_is_refused() {
        let result = SessionTimeoutPolicy::new(lifetime(600), IdleTimeout::After(lifetime(601)));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A 600 second session with a 600 second idle timeout is accepted.
    #[test]
    fn an_idle_timeout_equal_to_the_session_is_allowed() {
        assert!(
            SessionTimeoutPolicy::new(lifetime(600), IdleTimeout::After(lifetime(600))).is_ok()
        );
    }

    /// Under the standard policy, a session expires exactly 24 hours after
    /// it was created.
    #[test]
    fn absolute_expiry_computation() {
        let created = now();

        let expiry = SessionTimeoutPolicy::STANDARD.absolute_expiry(created);

        assert_eq!((expiry - created).whole_seconds(), 86_400);
    }

    /// Under the standard 30 minute idle timeout, a session last used 10
    /// minutes ago is not idle.
    #[test]
    fn not_idle_when_recently_active() {
        let last_active = now();

        assert!(
            !SessionTimeoutPolicy::STANDARD
                .is_idle(last_active, last_active + Duration::minutes(10))
        );
    }

    /// Under the standard policy, a session last used 31 minutes ago is idle.
    #[test]
    fn idle_after_timeout() {
        let last_active = now();

        assert!(
            SessionTimeoutPolicy::STANDARD
                .is_idle(last_active, last_active + Duration::minutes(31))
        );
    }

    /// Under the relaxed policy, which never idles out, a session unused for
    /// 24 hours is not idle.
    #[test]
    fn not_idle_when_the_policy_has_no_idle_timeout() {
        let last_active = now();

        assert!(
            !SessionTimeoutPolicy::RELAXED.is_idle(last_active, last_active + Duration::hours(24))
        );
    }

    /// A session last used exactly 1800 seconds ago is already idle under
    /// the 30 minute timeout.
    #[test]
    fn idle_at_exact_boundary() {
        let last_active = now();

        assert!(
            SessionTimeoutPolicy::STANDARD
                .is_idle(last_active, last_active + Duration::seconds(1800))
        );
    }
}
