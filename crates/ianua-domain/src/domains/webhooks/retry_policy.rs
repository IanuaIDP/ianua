//! How failed webhook deliveries are retried, and when a subscription is
//! switched off.

use std::num::NonZeroU32;

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::types::{FailureLimit, Seconds};

/// How a tenant's failed webhook deliveries are retried.
///
/// Delivery reads it to space out retries. It also says how many failures
/// in a row switch a subscription off.
#[derive(Debug, Clone)]
pub struct WebhookRetryPolicy {
    /// Maximum number of retry attempts per delivery.
    max_retries: u8,
    /// The wait before the first retry, in seconds.
    initial_delay_seconds: Seconds,
    /// How much the delay grows after each retry. With 2.0, each retry
    /// waits twice as long as the one before.
    backoff_multiplier: f32,
    /// Maximum delay between retries, in seconds. The growing delay stops
    /// here.
    max_delay_seconds: Seconds,
    /// Consecutive failures, across all events, after which the
    /// subscription is switched off.
    disable_after_failures: FailureLimit,
    /// How long each delivery may take, in seconds. An upstream that does
    /// not answer in time counts as timed out.
    timeout_seconds: Seconds,
}

/// The settings a webhook retry policy is built from.
#[derive(Clone, Copy)]
pub struct RetryPolicyParams {
    /// How many times a delivery is retried.
    pub max_retries: u8,
    /// The wait before the first retry.
    pub initial_delay_seconds: Seconds,
    /// How much each wait grows.
    pub backoff_multiplier: f32,
    /// The longest wait.
    pub max_delay_seconds: Seconds,
    /// Consecutive failures after which the endpoint is switched off.
    pub disable_after_failures: u32,
    /// How long one delivery may take.
    pub timeout_seconds: Seconds,
}

impl WebhookRetryPolicy {
    /// The standard policy's limit: off after 50 failures in a row.
    ///
    /// It is built at compile time, so the `unwrap` cannot fail at run time.
    const STANDARD_FAILURE_LIMIT: FailureLimit =
        FailureLimit::from_count(NonZeroU32::new(50).unwrap());
    /// The aggressive policy's limit: off after 20 failures in a row.
    const AGGRESSIVE_FAILURE_LIMIT: FailureLimit =
        FailureLimit::from_count(NonZeroU32::new(20).unwrap());
    /// The patient policy's limit: off after 100 failures in a row.
    const PATIENT_FAILURE_LIMIT: FailureLimit =
        FailureLimit::from_count(NonZeroU32::new(100).unwrap());

    /// Builds a retry policy, once its settings pass the checks below.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] for a multiplier outside 1..=10 or not a
    /// number, more than 20 retries, a delay above one day, or an initial delay above
    /// the maximum. The failure threshold must be 1..=1,000 and the delivery timeout
    /// must be greater than zero and no more than two minutes.
    pub fn new(params: RetryPolicyParams) -> Result<Self, DomainError> {
        ensure_policy_holds(&params)?;
        let RetryPolicyParams {
            max_retries,
            initial_delay_seconds,
            backoff_multiplier,
            max_delay_seconds,
            disable_after_failures,
            timeout_seconds,
        } = params;
        Ok(Self {
            max_retries,
            initial_delay_seconds,
            backoff_multiplier,
            max_delay_seconds,
            disable_after_failures: FailureLimit::new(disable_after_failures)?,
            timeout_seconds,
        })
    }

    /// The default for most tenants.
    ///
    /// 5 retries, a first wait of 10 seconds that doubles each time up to 5
    /// minutes, and a 30 second timeout. Off after 50 failures in a row.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            max_retries: 5,
            initial_delay_seconds: Seconds::new(10),
            backoff_multiplier: 2.0,
            max_delay_seconds: Seconds::new(300),
            disable_after_failures: Self::STANDARD_FAILURE_LIMIT,
            timeout_seconds: Seconds::new(30),
        }
    }

    /// A quick policy for integrations that need events fast.
    ///
    /// 3 retries, a first wait of 1 second that doubles each time up to 30
    /// seconds, and a 10 second timeout. Off after 20 failures in a row.
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            max_retries: 3,
            initial_delay_seconds: Seconds::new(1),
            backoff_multiplier: 2.0,
            max_delay_seconds: Seconds::new(30),
            disable_after_failures: Self::AGGRESSIVE_FAILURE_LIMIT,
            timeout_seconds: Seconds::new(10),
        }
    }

    /// A patient policy for endpoints that are often down.
    ///
    /// 10 retries, a first wait of 30 seconds that triples each time up to
    /// an hour, and a 60 second timeout. Off after 100 failures in a row.
    #[must_use]
    pub fn patient() -> Self {
        Self {
            max_retries: 10,
            initial_delay_seconds: Seconds::new(30),
            backoff_multiplier: 3.0,
            max_delay_seconds: Seconds::new(3600),
            disable_after_failures: Self::PATIENT_FAILURE_LIMIT,
            timeout_seconds: Seconds::new(60),
        }
    }

    /// Maximum retry attempts per delivery.
    #[must_use]
    pub fn max_retries(&self) -> u8 {
        self.max_retries
    }

    /// The wait before the first retry, in seconds.
    #[must_use]
    pub fn initial_delay_seconds(&self) -> Seconds {
        self.initial_delay_seconds
    }

    /// Backoff multiplier between retries.
    #[must_use]
    pub fn backoff_multiplier(&self) -> f32 {
        self.backoff_multiplier
    }

    /// The longest wait between retries, in seconds.
    #[must_use]
    pub fn max_delay_seconds(&self) -> Seconds {
        self.max_delay_seconds
    }

    /// Consecutive failures after which the subscription is switched off.
    #[must_use]
    pub fn disable_after_failures(&self) -> FailureLimit {
        self.disable_after_failures
    }

    /// How long one delivery may take, in seconds.
    #[must_use]
    pub fn timeout_seconds(&self) -> Seconds {
        self.timeout_seconds
    }

    /// The delay in seconds before try number `attempt`.
    ///
    /// Try 0 is the first try and waits nothing. Retry `n` waits
    /// `initial * multiplier^(n - 1)`, but never more than
    /// `max_delay_seconds`.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u8) -> u32 {
        let Some(retries) = attempt.checked_sub(1) else {
            return 0;
        };

        let delay = f64::from(self.initial_delay_seconds.get())
            * f64::from(self.backoff_multiplier).powi(i32::from(retries));
        whole_seconds(delay.clamp(0.0, f64::from(self.max_delay_seconds.get())))
    }

    /// Whether this many consecutive failures switch the subscription off.
    #[must_use]
    pub fn should_disable(&self, consecutive_failures: u32) -> bool {
        consecutive_failures >= self.disable_after_failures.get()
    }
}

/// The retry policy a webhook subscription chose.
///
/// Each names one of the policies above. A tenant picks how hard delivery
/// tries per endpoint: fast for an integration that needs events quickly,
/// patient for an endpoint that is often down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RetryPreset {
    /// [`WebhookRetryPolicy::standard`].
    Standard,
    /// [`WebhookRetryPolicy::aggressive`].
    Aggressive,
    /// [`WebhookRetryPolicy::patient`].
    Patient,
}

impl RetryPreset {
    /// The policy it names.
    #[must_use]
    pub fn policy(self) -> WebhookRetryPolicy {
        match self {
            Self::Standard => WebhookRetryPolicy::standard(),
            Self::Aggressive => WebhookRetryPolicy::aggressive(),
            Self::Patient => WebhookRetryPolicy::patient(),
        }
    }

    /// The name it is shown and recorded under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Aggressive => "aggressive",
            Self::Patient => "patient",
        }
    }
}

/// A delay already clamped to `0..=max_delay_seconds` as whole seconds.
///
/// The value lies in the range of a `u32`, so the cast neither wraps nor
/// loses a sign. Dropping the fraction is intended.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn whole_seconds(clamped: f64) -> u32 {
    clamped as u32
}

/// The most retries one delivery gets.
const MAX_RETRIES: u8 = 20;
/// The fastest a wait may grow per retry.
const MAX_BACKOFF: f32 = 10.0;
/// The longest wait between two retries: a day.
const MAX_DELAY_SECONDS: u32 = 86_400;
/// The most consecutive failures an endpoint may run up before it is off.
const MAX_FAILURES_BEFORE_DISABLE: u32 = 1_000;
/// The longest one delivery may hold a worker.
const MAX_TIMEOUT_SECONDS: u32 = 120;

/// Checks the rules a retry policy keeps.
///
/// The backoff never shrinks the wait. The first delay is no longer than
/// the longest. The failure threshold and the delivery timeout are not zero.
///
/// Every number also has an upper limit. A worker waits on each delivery
/// for the timeout, and each retry stays queued for its delay. Without the
/// limits, one tenant's endpoint could hold workers and queue space forever.
fn ensure_policy_holds(params: &RetryPolicyParams) -> Result<(), DomainError> {
    let multiplier = params.backoff_multiplier;
    if !(1.0..=MAX_BACKOFF).contains(&multiplier) {
        return Err(DomainError::invalid(message!(
            "webhooks-the-backoff-multiplier-must-be-a",
            format!("the backoff multiplier must be a number from 1 to {MAX_BACKOFF}")
        )));
    }
    validate_range("max_retries", params.max_retries, 0..=MAX_RETRIES)?;
    validate_range(
        "max_delay_seconds",
        params.max_delay_seconds.get(),
        0..=MAX_DELAY_SECONDS,
    )?;
    validate_range(
        "initial_delay_seconds",
        params.initial_delay_seconds.get(),
        0..=params.max_delay_seconds.get(),
    )?;
    validate_range(
        "disable_after_failures",
        params.disable_after_failures,
        1..=MAX_FAILURES_BEFORE_DISABLE,
    )?;
    validate_range(
        "timeout_seconds",
        params.timeout_seconds.get(),
        1..=MAX_TIMEOUT_SECONDS,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default policy retries five times, waits ten seconds first and
    /// gives each delivery thirty seconds.
    #[test]
    fn the_standard_policy_retries_five_times_from_ten_seconds() {
        let p = WebhookRetryPolicy::standard();
        assert_eq!(p.max_retries(), 5);
        assert_eq!(p.initial_delay_seconds(), Seconds::new(10));
        assert_eq!(p.timeout_seconds(), Seconds::new(30));
    }

    /// The default policy reports a multiplier of 2, a longest wait of 300
    /// seconds and a limit of 50 failures. Delivery spaces retries and
    /// switches endpoints off from these numbers.
    #[test]
    fn the_backoff_numbers_read_back_as_configured() {
        let p = WebhookRetryPolicy::standard();

        assert!((p.backoff_multiplier() - 2.0).abs() < f32::EPSILON);
        assert_eq!(p.max_delay_seconds(), Seconds::new(300));
        assert_eq!(p.disable_after_failures().get(), 50);
    }

    /// Ann picks the patient preset for an endpoint that is often down. It
    /// names the policy of ten retries from thirty seconds; the quick
    /// preset names three retries.
    #[test]
    fn a_preset_names_its_policy() {
        let patient = RetryPreset::Patient.policy();
        let quick = RetryPreset::Aggressive.policy();

        assert_eq!(patient.max_retries(), 10);
        assert_eq!(patient.initial_delay_seconds(), Seconds::new(30));
        assert_eq!(quick.max_retries(), 3);
        assert_eq!(RetryPreset::Standard.policy().max_retries(), 5);
    }

    /// The quick policy retries three times and waits one second first.
    #[test]
    fn the_aggressive_policy_retries_three_times_from_one_second() {
        let p = WebhookRetryPolicy::aggressive();
        assert_eq!(p.max_retries(), 3);
        assert_eq!(p.initial_delay_seconds(), Seconds::new(1));
    }

    /// Try 0 is the first delivery, not a retry. It is sent at once.
    #[test]
    fn first_attempt_has_no_delay() {
        let p = WebhookRetryPolicy::standard();
        assert_eq!(p.delay_for_attempt(0), 0);
    }

    /// Under the default policy, the first retry waits the first delay of
    /// ten seconds, with no growth yet.
    #[test]
    fn first_retry_uses_initial_delay() {
        let p = WebhookRetryPolicy::standard();
        assert_eq!(p.delay_for_attempt(1), 10);
    }

    /// Under the default policy, retries one to five wait 10, 20, 40, 80
    /// and 160 seconds.
    #[test]
    fn each_retry_waits_twice_as_long_as_the_last() {
        let p = WebhookRetryPolicy::standard();

        assert_eq!(p.delay_for_attempt(1), 10);
        assert_eq!(p.delay_for_attempt(2), 20);
        assert_eq!(p.delay_for_attempt(3), 40);
        assert_eq!(p.delay_for_attempt(4), 80);
        assert_eq!(p.delay_for_attempt(5), 160);
    }

    /// Retry 10 under the default policy would wait 10 times 2 to the 9th,
    /// which is 5120 seconds. It waits the longest allowed, 300, instead.
    #[test]
    fn delay_capped_at_max() {
        let p = WebhookRetryPolicy::standard();
        assert_eq!(p.delay_for_attempt(10), 300);
    }

    /// With a limit of 50, an endpoint with 49 failures in a row stays on.
    /// At 50 or 51 it is switched off.
    #[test]
    fn should_disable_at_threshold() {
        let p = WebhookRetryPolicy::standard();
        assert!(!p.should_disable(49));
        assert!(p.should_disable(50));
        assert!(p.should_disable(51));
    }

    /// A valid starting policy for checking one changed setting at a time.
    fn params() -> RetryPolicyParams {
        RetryPolicyParams {
            max_retries: 5,
            initial_delay_seconds: Seconds::new(10),
            backoff_multiplier: 2.0,
            max_delay_seconds: Seconds::new(300),
            disable_after_failures: 50,
            timeout_seconds: Seconds::new(30),
        }
    }

    /// A tenant picks the same numbers as the default policy. They are
    /// accepted.
    #[test]
    fn a_sensible_policy_is_accepted() {
        assert!(WebhookRetryPolicy::new(params()).is_ok());
    }

    /// A multiplier of 0.5 is refused, since it would shrink each wait. Not
    /// a number and infinity are refused too.
    #[test]
    fn a_backoff_below_one_or_not_a_number_is_refused() {
        for backoff_multiplier in [0.5, f32::NAN, f32::INFINITY] {
            let result = WebhookRetryPolicy::new(RetryPolicyParams {
                backoff_multiplier,
                ..params()
            });
            assert!(result.is_err(), "{backoff_multiplier} was accepted");
        }
    }

    /// A first wait of 301 seconds with a longest wait of 300 is refused.
    #[test]
    fn a_first_delay_longer_than_the_longest_is_refused() {
        let result = WebhookRetryPolicy::new(RetryPolicyParams {
            initial_delay_seconds: Seconds::new(301),
            ..params()
        });

        assert!(result.is_err());
    }

    /// A failure limit of zero is refused, since it would switch an endpoint
    /// off before any failure. A timeout of zero is refused, since every
    /// delivery would time out.
    #[test]
    fn a_zero_threshold_or_timeout_is_refused() {
        let no_threshold = RetryPolicyParams {
            disable_after_failures: 0,
            ..params()
        };
        let no_timeout = RetryPolicyParams {
            timeout_seconds: Seconds::new(0),
            ..params()
        };

        assert!(WebhookRetryPolicy::new(no_threshold).is_err());
        assert!(WebhookRetryPolicy::new(no_timeout).is_err());
    }

    /// A valid retry policy is accepted, while values above the retry,
    /// backoff, delay, failure threshold and timeout ceilings are refused.
    #[test]
    fn numbers_past_their_ceiling_are_refused() {
        let too_far = [
            RetryPolicyParams {
                max_retries: 21,
                ..params()
            },
            RetryPolicyParams {
                backoff_multiplier: 10.5,
                ..params()
            },
            RetryPolicyParams {
                max_delay_seconds: Seconds::new(86_401),
                ..params()
            },
            RetryPolicyParams {
                disable_after_failures: 1_001,
                ..params()
            },
            RetryPolicyParams {
                timeout_seconds: Seconds::new(121),
                ..params()
            },
        ];

        assert!(WebhookRetryPolicy::new(params()).is_ok());
        for params in too_far {
            assert!(WebhookRetryPolicy::new(params).is_err());
        }
    }
}
