//! Per-user rate limiting middleware for security-sensitive endpoints.
//!
//! Limits requests per authenticated user, at so many per window, with an
//! allowance that refills evenly across the window, so no stretch of that
//! length lets through more than the limit. Applied to
//! endpoints where a compromised session could cause damage:
//! break_glass, mfa_enroll, device trust, password change.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use ianua_app::context::CallerIdentity;
use ianua_app::ports::shared::ResolvedCaller;
use ianua_domain::message;
use ianua_domain::shared::security::allowance::{Allowance, Rate};
use ianua_domain::types::UserId;

/// The most people tracked at once. Past it, those whose allowance is full
/// again are forgotten, which changes nothing for them.
const MAX_TRACKED_PEOPLE: usize = 100_000;

/// Configuration for per-user rate limiting.
#[derive(Clone)]
pub(crate) struct UserRateLimitConfig {
    /// Maximum requests per user per window, the most the allowance holds.
    pub max_requests: u32,
    /// The window over which the allowance refills.
    pub window: Duration,
}

/// Shared state for per-user rate limiting.
#[derive(Clone)]
pub(crate) struct UserRateLimitState {
    config: UserRateLimitConfig,
    counters: Arc<RwLock<HashMap<UserId, Allowance>>>,
}

impl UserRateLimitState {
    /// Creates a new rate limit state.
    #[must_use]
    pub(crate) fn new(config: UserRateLimitConfig) -> Self {
        Self {
            config,
            counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Spends one request of `user_id`'s allowance and says whether it was
    /// there to spend.
    fn check_and_increment(&self, user_id: UserId) -> bool {
        let now = Instant::now();
        let rate = Rate::new(self.config.max_requests, self.config.window);
        let mut counters = self
            .counters
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if counters.len() >= MAX_TRACKED_PEOPLE {
            counters.retain(|_, allowance| !allowance.is_full_at(rate, now));
        }
        counters
            .entry(user_id)
            .or_insert_with(|| Allowance::full(rate, now))
            .spend(rate, now)
            .is_some()
    }
}

/// Axum middleware function for per-user rate limiting.
///
/// Skips unauthenticated requests (they're handled by IP rate limiting).
/// Skips operators (no user-level rate limit for platform engineers).
pub(crate) async fn user_rate_limit(
    State(state): State<UserRateLimitState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let person = request
        .extensions()
        .get::<ResolvedCaller>()
        .and_then(|caller| counted_person(caller.identity));

    let Some(person) = person else {
        return next.run(request).await;
    };

    if !state.check_and_increment(person) {
        return crate::error::answered(
            StatusCode::TOO_MANY_REQUESTS,
            crate::error::ErrorCode::RateLimitExceeded,
            message!(
                "api-too-many-security-sensitive-requests",
                "too many security-sensitive requests"
            ),
        );
    }

    next.run(request).await
}

/// The person a request is counted against: a tenant user, or an
/// organization member under the same id. Operators are not counted.
fn counted_person(identity: CallerIdentity) -> Option<UserId> {
    match identity {
        CallerIdentity::TenantUser(id) => Some(id),
        CallerIdentity::OrgUser(id) => Some(UserId::from_uuid(*id.as_uuid())),
        CallerIdentity::Operator(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ann may make as many requests as the limit allows.
    #[test]
    fn allows_under_limit() {
        let state = UserRateLimitState::new(UserRateLimitConfig {
            max_requests: 3,
            window: Duration::from_secs(60),
        });
        let uid = UserId::new();

        assert!(state.check_and_increment(uid));
        assert!(state.check_and_increment(uid));
        assert!(state.check_and_increment(uid));
    }

    /// Two requests consume the user's allowance and the third is refused.
    #[test]
    fn rejects_over_limit() {
        let state = UserRateLimitState::new(UserRateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(60),
        });
        let uid = UserId::new();

        assert!(state.check_and_increment(uid));
        assert!(state.check_and_increment(uid));
        assert!(!state.check_and_increment(uid));
    }

    /// Ann using up her limit does not use up Bob's.
    #[test]
    fn different_users_have_separate_counters() {
        let state = UserRateLimitState::new(UserRateLimitConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
        });
        let u1 = UserId::new();
        let u2 = UserId::new();

        assert!(state.check_and_increment(u1));
        assert!(!state.check_and_increment(u1));
        assert!(state.check_and_increment(u2));
    }

    /// Spending the full allowance leaves no capacity for an immediate retry.
    #[test]
    fn a_burst_at_the_turn_of_a_window_gets_no_second_allowance() {
        let state = UserRateLimitState::new(UserRateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(300),
        });
        let uid = UserId::new();
        state.check_and_increment(uid);
        state.check_and_increment(uid);

        assert!(!state.check_and_increment(uid));
    }
}
