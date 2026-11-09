//! The numbers every sign-in configuration sets, tenant or organization, and
//! the ranges they must stay in.

use std::num::NonZeroU32;

use crate::domains::authentication::risk_engine::rate_limit::RateLimitPolicy;
use crate::domains::authentication::sessions::timeout::{IdleTimeout, SessionTimeoutPolicy};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::types::{Lifetime, Seconds};

/// Five minutes. A shorter session expires in the middle of a task.
pub(crate) const MIN_SESSION_SECS: u32 = 300;

/// Thirty days.
pub(crate) const MAX_SESSION_SECS: u32 = 2_592_000;

/// One minute.
pub(crate) const MIN_IDLE_SECS: u32 = 60;

/// The fewest failed attempts before a lockout. With one, a single typo
/// locks the person's own network out of their account.
pub(crate) const MIN_LOGIN_ATTEMPTS: u8 = 2;

/// The most failed attempts before a lockout. Past this, the lockout does
/// not slow down guessing.
pub(crate) const MAX_LOGIN_ATTEMPTS: u8 = 100;

/// Thirty seconds.
pub(crate) const MIN_LOCKOUT_SECS: u32 = 30;

/// One day.
pub(crate) const MAX_LOCKOUT_SECS: u32 = 86_400;

/// The numbers a sign-in configuration sets, before they are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignInNumbers {
    /// How long a session lasts from when it starts, in seconds.
    pub session_lifetime_secs: Seconds,
    /// How long a session may go unused, in seconds.
    pub idle_timeout_secs: Seconds,
    /// Failed attempts from one network before it is locked out of the
    /// account.
    pub max_login_attempts: u8,
    /// How long a network stays locked out of the account, in seconds.
    pub lockout_duration_secs: Seconds,
}

/// The numbers a sign-in configuration sets, each in its range and none
/// contradicting another.
///
/// Only [`new`](Self::new) makes one, so the session and lockout policies
/// drawn from it never rest on a one-attempt lockout or a session past
/// thirty days.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignInLimits(SignInNumbers);

impl SignInLimits {
    /// Checks sign-in limits individually and against each other.
    ///
    /// # Errors
    /// [`DomainError::Validation`] for sessions outside five minutes to thirty days,
    /// idle timeouts below one minute or above the session lifetime, attempt counts
    /// outside `MIN_LOGIN_ATTEMPTS` to `MAX_LOGIN_ATTEMPTS`, or lockouts outside
    /// thirty seconds to one day.
    pub fn new(numbers: SignInNumbers) -> Result<Self, DomainError> {
        ensure_session_holds_together(&numbers)?;
        ensure_lockout_in_range(&numbers)?;
        Ok(Self(numbers))
    }

    /// Numbers a configuration already ran through [`new`](Self::new) when
    /// it was made.
    pub(crate) fn from_checked(numbers: SignInNumbers) -> Self {
        Self(numbers)
    }

    /// How long a session lasts from when it starts, in seconds.
    #[must_use]
    pub fn session_lifetime_secs(&self) -> Seconds {
        self.0.session_lifetime_secs
    }

    /// How long a session may go unused, in seconds.
    #[must_use]
    pub fn idle_timeout_secs(&self) -> Seconds {
        self.0.idle_timeout_secs
    }

    /// Failed attempts from one network before it is locked out of the
    /// account.
    #[must_use]
    pub fn max_login_attempts(&self) -> u8 {
        self.0.max_login_attempts
    }

    /// How long a network stays locked out of the account, in seconds.
    #[must_use]
    pub fn lockout_duration_secs(&self) -> Seconds {
        self.0.lockout_duration_secs
    }

    /// These limits as the timeout policy every session started under them
    /// follows.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the session lifetime or the idle
    ///   timeout is zero.
    /// - [`DomainError::Validation`] when the idle timeout outlasts the
    ///   session.
    pub fn session_timeout(&self) -> Result<SessionTimeoutPolicy, DomainError> {
        let absolute = Lifetime::seconds(i64::from(self.0.session_lifetime_secs.get()))?;
        let idle = Lifetime::seconds(i64::from(self.0.idle_timeout_secs.get()))?;
        SessionTimeoutPolicy::new(absolute, IdleTimeout::After(idle))
    }

    /// These limits as the rule for locking a network out of an account
    /// after failed sign-ins from it, counted over the default window.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the attempt count or the lockout
    ///   length is zero.
    pub fn lockout(&self) -> Result<RateLimitPolicy, DomainError> {
        let attempts = NonZeroU32::new(u32::from(self.0.max_login_attempts)).ok_or_else(|| {
            DomainError::invalid(message!(
                "authentication-max-login-attempts-must-be-at",
                "max_login_attempts must be at least one"
            ))
        })?;
        let lockout = Lifetime::seconds(i64::from(self.0.lockout_duration_secs.get()))?;
        Ok(RateLimitPolicy::new(
            attempts,
            lockout,
            RateLimitPolicy::DEFAULT.window(),
        ))
    }
}

fn ensure_session_holds_together(numbers: &SignInNumbers) -> Result<(), DomainError> {
    validate_range(
        "session_lifetime_secs",
        numbers.session_lifetime_secs.get(),
        MIN_SESSION_SECS..=MAX_SESSION_SECS,
    )?;
    validate_range(
        "idle_timeout_secs",
        numbers.idle_timeout_secs.get(),
        MIN_IDLE_SECS..=u32::MAX,
    )?;
    if numbers.idle_timeout_secs.get() > numbers.session_lifetime_secs.get() {
        return Err(DomainError::invalid(message!(
            "authentication-an-idle-timeout-of-s-cannot",
            format!(
                "an idle timeout of {}s cannot outlast the {}s session it belongs to",
                numbers.idle_timeout_secs, numbers.session_lifetime_secs
            )
        )));
    }
    Ok(())
}

fn ensure_lockout_in_range(numbers: &SignInNumbers) -> Result<(), DomainError> {
    validate_range(
        "max_login_attempts",
        numbers.max_login_attempts,
        MIN_LOGIN_ATTEMPTS..=MAX_LOGIN_ATTEMPTS,
    )?;
    validate_range(
        "lockout_duration_secs",
        numbers.lockout_duration_secs.get(),
        MIN_LOCKOUT_SECS..=MAX_LOCKOUT_SECS,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbers() -> SignInNumbers {
        SignInNumbers {
            session_lifetime_secs: Seconds::new(3_600),
            idle_timeout_secs: Seconds::new(600),
            max_login_attempts: 5,
            lockout_duration_secs: Seconds::new(300),
        }
    }

    /// A one hour session, 10 minute idle timeout, 5 attempts and a 5 minute
    /// lockout are all in range and make limits.
    #[test]
    fn numbers_in_range_make_limits() {
        assert!(SignInLimits::new(numbers()).is_ok());
    }

    /// A tenant sets lockout after 1 failed attempt. It is refused, because a
    /// single typo would lock the account.
    #[test]
    fn a_one_attempt_lockout_is_refused() {
        let one = SignInNumbers {
            max_login_attempts: 1,
            ..numbers()
        };

        assert!(SignInLimits::new(one).is_err());
    }

    /// A 10 second idle timeout is refused for being too short. The message
    /// does not claim it outlasts the one hour session it sits inside.
    #[test]
    fn a_too_short_idle_timeout_is_refused_for_its_length() {
        let short = SignInNumbers {
            idle_timeout_secs: Seconds::new(10),
            ..numbers()
        };

        let refused = SignInLimits::new(short).unwrap_err().to_string();

        assert!(!refused.contains("outlast"), "{refused}");
    }

    /// A two hour idle timeout on a one hour session is refused.
    #[test]
    fn an_idle_timeout_longer_than_the_session_is_refused() {
        let longer = SignInNumbers {
            idle_timeout_secs: Seconds::new(7_200),
            ..numbers()
        };

        assert!(SignInLimits::new(longer).is_err());
    }
}
