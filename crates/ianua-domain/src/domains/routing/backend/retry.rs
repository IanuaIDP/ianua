//! Trying a request again when its upstream failed it.
//!
//! A backend restarting, or one replica out of several dropping a
//! connection, fails a request that a second try would have served. So a
//! service may ask the gateway to try again, and says when.
//!
//! A retry sends the same request twice. For a read that changes nothing.
//! For a payment it may charge twice. So a request that changes something is
//! only tried again when the service retries every method, and only when it
//! never reached the backend at all.

use time::Duration;

use crate::shared::validation::ValidationError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::types::HttpMethod;

/// How an upstream failed a request, as far as retrying goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RetryOn {
    /// No connection to the backend could be opened, so nothing was sent.
    ConnectFailure,
    /// The backend answered `502 Bad Gateway`.
    BadGateway,
    /// The backend answered `503 Service Unavailable`.
    Unavailable,
    /// The backend answered `504 Gateway Timeout`.
    GatewayTimeout,
}

impl RetryOn {
    /// The failure an upstream status is, when it is one a retry is ever
    /// made on.
    #[must_use]
    pub fn of_status(status: u16) -> Option<Self> {
        match status {
            502 => Some(Self::BadGateway),
            503 => Some(Self::Unavailable),
            504 => Some(Self::GatewayTimeout),
            _ => None,
        }
    }

    /// Whether the request may have reached the backend before it failed.
    fn may_have_arrived(self) -> bool {
        !matches!(self, Self::ConnectFailure)
    }
}

/// Which requests are tried again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RetriedMethods {
    /// Only methods that change nothing more when sent twice: `GET`, `HEAD`,
    /// `OPTIONS`, `PUT` and `DELETE`.
    IdempotentOnly,
    /// Every method. Allowed only when the policy retries on a connection
    /// that could not be opened and nothing else, so a request that changes
    /// something is never sent twice.
    Every,
}

/// The settings a retry policy is built from.
pub struct UpstreamRetryParams {
    /// How many times a request is sent at most, the first try included.
    pub attempts: u8,
    /// The failures a request is tried again on.
    pub retry_on: Vec<RetryOn>,
    /// Which requests are tried again.
    pub methods: RetriedMethods,
    /// The wait before the first retry, in milliseconds. It doubles for
    /// each retry after.
    pub base_backoff_ms: u32,
    /// The longest wait between two tries, in milliseconds.
    pub max_backoff_ms: u32,
}

/// When and how often the gateway tries a failed request again.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "RetryPolicyRecord", into = "RetryPolicyRecord")
)]
pub struct RetryPolicy {
    attempts: u8,
    retry_on: Vec<RetryOn>,
    methods: RetriedMethods,
    base_backoff_ms: u32,
    max_backoff_ms: u32,
}

/// What the gateway does with a request its upstream just failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Send it again after this wait.
    RetryAfter(Duration),
    /// Answer the client with the failure.
    GiveUp,
}

impl RetryPolicy {
    /// The most tries a request gets, the first included.
    pub const MAX_ATTEMPTS: u8 = 5;

    /// The longest wait between two tries, in milliseconds.
    pub const MAX_BACKOFF_MS: u32 = 30_000;

    /// A checked retry policy.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `attempts` is outside `2..=5`. One attempt
    ///   is no retry at all.
    /// - [`ValidationError`] when no failure is named, or one twice.
    /// - [`ValidationError`] when the first wait is outside `10..=5000`
    ///   milliseconds, or the longest is below it or above 30 seconds.
    /// - [`ValidationError`] when every method is retried on a failure the
    ///   request may have arrived before.
    pub fn new(params: UpstreamRetryParams) -> Result<Self, ValidationError> {
        validate_range("attempts", params.attempts, 2..=Self::MAX_ATTEMPTS)?;
        validate_count("retry_on", params.retry_on.len(), 1..=4)?;
        if first_repeat(&params.retry_on).is_some() {
            return Err(invalid("a failure is named twice"));
        }
        validate_range("base_backoff_ms", params.base_backoff_ms, 10..=5_000)?;
        validate_range(
            "max_backoff_ms",
            params.max_backoff_ms,
            params.base_backoff_ms..=Self::MAX_BACKOFF_MS,
        )?;
        let reaches_backend = params.retry_on.iter().any(|on| on.may_have_arrived());
        if params.methods == RetriedMethods::Every && reaches_backend {
            return Err(invalid(
                "every method is retried only on a connection that could not be opened; a \
                 request that changes something is never sent twice",
            ));
        }
        Ok(Self {
            attempts: params.attempts,
            retry_on: params.retry_on,
            methods: params.methods,
            base_backoff_ms: params.base_backoff_ms,
            max_backoff_ms: params.max_backoff_ms,
        })
    }

    /// How many times a request is sent at most, the first try included.
    #[must_use]
    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    /// The failures a request is tried again on.
    #[must_use]
    pub fn retry_on(&self) -> &[RetryOn] {
        &self.retry_on
    }

    /// Which requests are tried again.
    #[must_use]
    pub fn methods(&self) -> RetriedMethods {
        self.methods
    }

    /// The wait before the first retry, in milliseconds.
    #[must_use]
    pub fn base_backoff_ms(&self) -> u32 {
        self.base_backoff_ms
    }

    /// The longest wait between two tries, in milliseconds.
    #[must_use]
    pub fn max_backoff_ms(&self) -> u32 {
        self.max_backoff_ms
    }

    /// What to do with a `method` request that failed with `failure` on
    /// try number `tried` (1 for the first).
    ///
    /// It gives up once the tries are spent, on a failure the policy does
    /// not name, on a method the policy does not retry, and on a request
    /// that changes something when it may have reached the backend. The
    /// wait doubles with each retry, up to the longest.
    #[must_use]
    pub fn decide(&self, method: HttpMethod, failure: RetryOn, tried: u8) -> RetryDecision {
        if tried >= self.attempts || !self.retry_on.contains(&failure) {
            return RetryDecision::GiveUp;
        }
        if !self.retries(method, failure) {
            return RetryDecision::GiveUp;
        }
        RetryDecision::RetryAfter(self.backoff_before(tried))
    }

    /// Whether a `method` request that failed with `failure` may be sent
    /// again: the policy's methods must cover it, and a request that
    /// changes something is never sent twice once it may have arrived.
    fn retries(&self, method: HttpMethod, failure: RetryOn) -> bool {
        match self.methods {
            RetriedMethods::IdempotentOnly => idempotent(method),
            RetriedMethods::Every => idempotent(method) || !failure.may_have_arrived(),
        }
    }

    /// The wait before the retry that follows try number `tried`.
    fn backoff_before(&self, tried: u8) -> Duration {
        let doublings = u32::from(tried.saturating_sub(1));
        let factor = 1u32.checked_shl(doublings).unwrap_or(u32::MAX);
        let wait = self
            .base_backoff_ms
            .saturating_mul(factor)
            .min(self.max_backoff_ms);
        Duration::milliseconds(i64::from(wait))
    }
}

/// [`RetryPolicy`] as stored, read back through [`RetryPolicy::new`].
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct RetryPolicyRecord {
    attempts: u8,
    retry_on: Vec<RetryOn>,
    methods: RetriedMethods,
    base_backoff_ms: u32,
    max_backoff_ms: u32,
}

#[cfg(feature = "serde")]
impl TryFrom<RetryPolicyRecord> for RetryPolicy {
    type Error = ValidationError;

    fn try_from(record: RetryPolicyRecord) -> Result<Self, Self::Error> {
        Self::new(UpstreamRetryParams {
            attempts: record.attempts,
            retry_on: record.retry_on,
            methods: record.methods,
            base_backoff_ms: record.base_backoff_ms,
            max_backoff_ms: record.max_backoff_ms,
        })
    }
}

#[cfg(feature = "serde")]
impl From<RetryPolicy> for RetryPolicyRecord {
    fn from(policy: RetryPolicy) -> Self {
        Self {
            attempts: policy.attempts,
            retry_on: policy.retry_on,
            methods: policy.methods,
            base_backoff_ms: policy.base_backoff_ms,
            max_backoff_ms: policy.max_backoff_ms,
        }
    }
}

/// Whether sending `method` twice changes nothing more than sending it once.
fn idempotent(method: HttpMethod) -> bool {
    matches!(
        method,
        HttpMethod::Get
            | HttpMethod::Head
            | HttpMethod::Options
            | HttpMethod::Put
            | HttpMethod::Delete
    )
}

/// The error a retry policy is refused with.
fn invalid(message: &str) -> ValidationError {
    ValidationError::Custom {
        field: "retry",
        code: "invalid_retry_policy".to_owned(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> UpstreamRetryParams {
        UpstreamRetryParams {
            attempts: 3,
            retry_on: vec![
                RetryOn::ConnectFailure,
                RetryOn::BadGateway,
                RetryOn::Unavailable,
            ],
            methods: RetriedMethods::IdempotentOnly,
            base_backoff_ms: 100,
            max_backoff_ms: 1_000,
        }
    }

    fn policy() -> RetryPolicy {
        RetryPolicy::new(params()).unwrap()
    }

    /// Ann's service retries three times. A `GET` answered `503` on the
    /// first try is sent again after 100 ms, and after 200 ms on the second.
    #[test]
    fn a_failed_read_is_retried_with_a_doubling_wait() {
        let policy = policy();

        assert_eq!(
            policy.decide(HttpMethod::Get, RetryOn::Unavailable, 1),
            RetryDecision::RetryAfter(Duration::milliseconds(100))
        );
        assert_eq!(
            policy.decide(HttpMethod::Get, RetryOn::Unavailable, 2),
            RetryDecision::RetryAfter(Duration::milliseconds(200))
        );
    }

    /// The third try of a `GET` fails too. With three tries spent, the
    /// gateway gives up.
    #[test]
    fn the_gateway_gives_up_once_the_tries_are_spent() {
        assert_eq!(
            policy().decide(HttpMethod::Get, RetryOn::Unavailable, 3),
            RetryDecision::GiveUp
        );
    }

    /// The policy names no `504`. A `GET` that timed out at the backend is
    /// not tried again.
    #[test]
    fn a_failure_the_policy_does_not_name_is_not_retried() {
        assert_eq!(
            policy().decide(HttpMethod::Get, RetryOn::GatewayTimeout, 1),
            RetryDecision::GiveUp
        );
    }

    /// The idempotent-only policy gives up on a POST that received a bad
    /// gateway response.
    #[test]
    fn a_change_that_may_have_arrived_is_not_retried() {
        assert_eq!(
            policy().decide(HttpMethod::Post, RetryOn::BadGateway, 1),
            RetryDecision::GiveUp
        );
    }

    /// The idempotent-only policy gives up on a POST even when its connection
    /// never opened.
    #[test]
    fn idempotent_only_never_retries_a_post() {
        assert_eq!(
            policy().decide(HttpMethod::Post, RetryOn::ConnectFailure, 1),
            RetryDecision::GiveUp
        );
    }

    /// Sam's service retries every method on a failed connection. Bob's
    /// `POST` never reached the backend, so it is sent again.
    #[test]
    fn every_method_retries_a_post_that_never_reached_the_backend() {
        let policy = RetryPolicy::new(UpstreamRetryParams {
            methods: RetriedMethods::Every,
            retry_on: vec![RetryOn::ConnectFailure],
            ..params()
        })
        .unwrap();

        assert!(matches!(
            policy.decide(HttpMethod::Post, RetryOn::ConnectFailure, 1),
            RetryDecision::RetryAfter(_)
        ));
    }

    /// Retrying every method is invalid when the policy includes backend
    /// responses. It is valid when limited to connection failures.
    #[test]
    fn every_method_is_retried_only_on_a_connection_that_never_opened() {
        let on_status = RetryPolicy::new(UpstreamRetryParams {
            methods: RetriedMethods::Every,
            ..params()
        });
        let on_connect = RetryPolicy::new(UpstreamRetryParams {
            methods: RetriedMethods::Every,
            retry_on: vec![RetryOn::ConnectFailure],
            ..params()
        });

        assert!(on_status.is_err());
        assert!(on_connect.is_ok());
    }

    /// Policies reject zero, one, six and one hundred attempts, all outside
    /// the allowed two-to-five range.
    #[test]
    fn the_number_of_tries_is_bounded() {
        for attempts in [0, 1, 6, 100] {
            assert!(
                RetryPolicy::new(UpstreamRetryParams {
                    attempts,
                    ..params()
                })
                .is_err(),
                "{attempts}"
            );
        }
    }

    /// A policy naming no failure, or `503` twice, is refused.
    #[test]
    fn the_failures_are_named_once_each() {
        let none = RetryPolicy::new(UpstreamRetryParams {
            retry_on: Vec::new(),
            ..params()
        });
        let twice = RetryPolicy::new(UpstreamRetryParams {
            retry_on: vec![RetryOn::Unavailable, RetryOn::Unavailable],
            ..params()
        });

        assert!(none.is_err());
        assert!(twice.is_err());
    }

    /// A longest wait shorter than the first, or above 30 seconds, is
    /// refused.
    #[test]
    fn the_longest_wait_is_at_least_the_first_and_at_most_thirty_seconds() {
        for max_backoff_ms in [50, 30_001] {
            assert!(
                RetryPolicy::new(UpstreamRetryParams {
                    max_backoff_ms,
                    ..params()
                })
                .is_err(),
                "{max_backoff_ms}"
            );
        }
    }

    /// With a first wait of 400 ms and a longest of 1000 ms, the fourth
    /// retry waits 1000 ms, not 3200.
    #[test]
    fn the_wait_never_grows_past_the_longest() {
        let policy = RetryPolicy::new(UpstreamRetryParams {
            attempts: 5,
            base_backoff_ms: 400,
            ..params()
        })
        .unwrap();

        assert_eq!(
            policy.decide(HttpMethod::Get, RetryOn::Unavailable, 4),
            RetryDecision::RetryAfter(Duration::milliseconds(1_000))
        );
    }

    /// What holds for every policy a service may set.
    mod invariants {
        use proptest::prelude::*;

        use super::*;

        fn failure() -> impl Strategy<Value = RetryOn> {
            prop_oneof![
                Just(RetryOn::ConnectFailure),
                Just(RetryOn::BadGateway),
                Just(RetryOn::Unavailable),
                Just(RetryOn::GatewayTimeout),
            ]
        }

        fn changing_method() -> impl Strategy<Value = HttpMethod> {
            prop_oneof![
                Just(HttpMethod::Post),
                Just(HttpMethod::Patch),
                Just(HttpMethod::Any)
            ]
        }

        fn methods() -> impl Strategy<Value = RetriedMethods> {
            prop_oneof![
                Just(RetriedMethods::IdempotentOnly),
                Just(RetriedMethods::Every)
            ]
        }

        proptest! {
            /// Whatever policy a service sets, a request that changes
            /// something and may have reached the backend is never sent
            /// again, and "idempotent only" never sends one again at all.
            #[test]
            fn a_change_is_never_sent_twice_against_the_policy(
                methods in methods(),
                retry_on in proptest::sample::subsequence(
                    vec![
                        RetryOn::ConnectFailure,
                        RetryOn::BadGateway,
                        RetryOn::Unavailable,
                        RetryOn::GatewayTimeout,
                    ],
                    1..=4,
                ),
                method in changing_method(),
                failed_with in failure(),
                tried in 1u8..=5,
            ) {
                let Ok(policy) = RetryPolicy::new(UpstreamRetryParams {
                    attempts: 5,
                    retry_on,
                    methods,
                    base_backoff_ms: 100,
                    max_backoff_ms: 1_000,
                }) else {
                    return Ok(());
                };

                let decision = policy.decide(method, failed_with, tried);

                let forbidden = methods == RetriedMethods::IdempotentOnly
                    || failed_with.may_have_arrived();
                prop_assert!(!forbidden || decision == RetryDecision::GiveUp);
            }
        }
    }

    /// `502`, `503` and `504` are failures a retry can name. `500` and `404`
    /// are not.
    #[test]
    fn only_gateway_statuses_are_retry_failures() {
        assert_eq!(RetryOn::of_status(503), Some(RetryOn::Unavailable));
        assert_eq!(RetryOn::of_status(500), None);
        assert_eq!(RetryOn::of_status(404), None);
    }

    /// A stored policy retrying every method on `503` is refused when read,
    /// as building it would be. A valid one reads back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_policy_is_held_to_the_same_rules() {
        let stored = serde_json::json!({
            "attempts": 3,
            "retry_on": ["unavailable"],
            "methods": "every",
            "base_backoff_ms": 100,
            "max_backoff_ms": 1000,
        });
        let json = serde_json::to_value(policy()).unwrap();

        assert!(serde_json::from_value::<RetryPolicy>(stored).is_err());
        assert_eq!(
            serde_json::from_value::<RetryPolicy>(json).unwrap(),
            policy()
        );
    }
}
