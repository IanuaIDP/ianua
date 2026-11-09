//! Per-caller rate limiting middleware.
//!
//! Reads the authenticated caller from request extensions, counts the
//! request against their budget (their tenant's, their organization's for a
//! member, their own for an operator), resolves the limit from their
//! organization's plan (cached by org_id), and checks the rate limiter.
//! Returns 429 Too Many Requests if the limit is exceeded.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use ianua_app::context::CallerIdentity;
use ianua_app::ports::limits::{RateBudget, RateLimiter};
use ianua_app::ports::organization::OrganizationStore;
use ianua_app::ports::shared::ResolvedCaller;
use ianua_domain::message;
use ianua_domain::types::OrganizationId;
use tower::{Layer, Service};

/// Cached rate limit per organization with expiry.
struct CachedLimit {
    limit: u32,
    expires_at: std::time::Instant,
}

/// Tower layer that applies per-caller rate limiting.
#[derive(Clone)]
pub(crate) struct RateLimitLayer {
    limiter: Arc<dyn RateLimiter>,
    plan_limits: Arc<PlanLimitCache>,
}

/// Each organization's per-minute limit, read from its plan and kept for a
/// while so a request does not cost a lookup.
pub(crate) struct PlanLimitCache {
    org_store: Arc<dyn OrganizationStore>,
    cached: RwLock<HashMap<OrganizationId, CachedLimit>>,
    fallback_per_minute: u32,
    ttl: std::time::Duration,
}

impl PlanLimitCache {
    /// A cache reading plans from `org_store`, keeping each answer for
    /// `ttl`, and answering `fallback_per_minute` for an organization whose
    /// plan cannot be read.
    #[must_use]
    pub(crate) fn new(
        org_store: Arc<dyn OrganizationStore>,
        fallback_per_minute: u32,
        ttl: std::time::Duration,
    ) -> Self {
        Self {
            org_store,
            cached: RwLock::new(HashMap::new()),
            fallback_per_minute,
            ttl,
        }
    }
}

impl RateLimitLayer {
    /// Creates a new rate limit layer.
    pub(crate) fn new(limiter: Arc<dyn RateLimiter>, plan_limits: Arc<PlanLimitCache>) -> Self {
        Self {
            limiter,
            plan_limits,
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
            plan_limits: self.plan_limits.clone(),
        }
    }
}

/// Tower service that enforces per-caller rate limits.
#[derive(Clone)]
pub(crate) struct RateLimitService<S> {
    inner: S,
    limiter: Arc<dyn RateLimiter>,
    plan_limits: Arc<PlanLimitCache>,
}

impl<S> Service<Request> for RateLimitService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let caller = request.extensions().get::<ResolvedCaller>().cloned();
        let limiter = self.limiter.clone();
        let plan_limits = self.plan_limits.clone();
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            let Some((caller, budget)) = caller.and_then(|caller| {
                let budget = budget_of(&caller)?;
                Some((caller, budget))
            }) else {
                return inner.call(request).await;
            };
            let limit = plan_limits.limit_for(&caller).await;

            match limiter.check_and_increment(&budget, limit).await {
                Ok(remaining) => {
                    let response = inner.call(request).await?;
                    Ok(with_rate_headers(response, remaining, limit))
                }
                Err(_) => Ok(crate::error::answered(
                    StatusCode::TOO_MANY_REQUESTS,
                    crate::error::ErrorCode::RateLimitExceeded,
                    message!("api-too-many-requests", "too many requests"),
                )),
            }
        })
    }
}

/// Reports the admitted caller's remaining allowance and configured limit.
fn with_rate_headers(mut response: Response, remaining: u32, limit: u32) -> Response {
    response
        .headers_mut()
        .insert("X-RateLimit-Remaining", remaining.into());
    response
        .headers_mut()
        .insert("X-RateLimit-Limit", limit.into());
    response
}

/// The budget `caller`'s requests count against, or `None` for a caller
/// the token resolver placed nowhere.
fn budget_of(caller: &ResolvedCaller) -> Option<RateBudget> {
    match caller.identity {
        CallerIdentity::Operator(operator) => Some(RateBudget::Operator(operator)),
        CallerIdentity::OrgUser(_) => caller.organization_id.map(RateBudget::Organization),
        CallerIdentity::TenantUser(_) => caller.tenant_id.map(RateBudget::Tenant),
    }
}

impl PlanLimitCache {
    /// The per-minute limit for `caller`: their organization's plan's, or
    /// the fallback for an operator, who belongs to none.
    async fn limit_for(&self, caller: &ResolvedCaller) -> u32 {
        let Some(organization_id) = caller.organization_id else {
            return self.fallback_per_minute;
        };
        self.per_minute(&organization_id).await
    }

    /// The organization's per-minute limit, from the cache while it is
    /// fresh and from its plan otherwise.
    async fn per_minute(&self, organization_id: &OrganizationId) -> u32 {
        let now = std::time::Instant::now();
        if let Some(limit) = self.fresh(organization_id, now) {
            return limit;
        }

        let limit = self
            .org_store
            .find_by_id(organization_id)
            .await
            .ok()
            .flatten()
            .map(|o| o.limits().api_rate_limit_per_minute)
            .unwrap_or(self.fallback_per_minute);

        self.cached
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                *organization_id,
                CachedLimit {
                    limit,
                    expires_at: now + self.ttl,
                },
            );
        limit
    }

    /// The cached limit, while it has not expired.
    fn fresh(&self, organization_id: &OrganizationId, now: std::time::Instant) -> Option<u32> {
        self.cached
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(organization_id)
            .filter(|cached| cached.expires_at > now)
            .map(|cached| cached.limit)
    }
}
