//! Plan limits, rate limits and mail throttles, as a test sets them.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantId};

use crate::test_support::Fake;

/// Limit enforcer that always allows. For tests.
pub struct FakeLimitEnforcer;

#[async_trait]
impl crate::ports::limits::LimitEnforcer for FakeLimitEnforcer {
    async fn check_tenant_limit(
        &self,
        _: &PlanLimits,
        _: &crate::tenancy::ScopedTenant,
        _: crate::ports::limits::ResourceKind,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn check_tenant_room(
        &self,
        _: &PlanLimits,
        _: &crate::tenancy::ScopedTenant,
        _: crate::ports::limits::ResourceKind,
        _: u64,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn tenant_room(
        &self,
        _: &PlanLimits,
        _: &crate::tenancy::ScopedTenant,
        _: crate::ports::limits::ResourceKind,
    ) -> Result<u64, DomainError> {
        Ok(u64::MAX)
    }

    async fn check_org_limit(
        &self,
        _: &PlanLimits,
        _: &OrganizationId,
        _: crate::ports::limits::ResourceKind,
    ) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Limit enforcer that always rejects. For plan limit enforcement tests.
pub struct RejectingLimitEnforcer;

#[async_trait]
impl crate::ports::limits::LimitEnforcer for RejectingLimitEnforcer {
    async fn check_tenant_limit(
        &self,
        _: &PlanLimits,
        _: &crate::tenancy::ScopedTenant,
        kind: crate::ports::limits::ResourceKind,
    ) -> Result<(), DomainError> {
        Err(DomainError::forbidden(format!(
            "plan limit reached: {kind:?}"
        )))
    }

    async fn check_tenant_room(
        &self,
        _: &PlanLimits,
        _: &crate::tenancy::ScopedTenant,
        kind: crate::ports::limits::ResourceKind,
        _: u64,
    ) -> Result<(), DomainError> {
        Err(DomainError::forbidden(format!(
            "plan limit reached: {kind:?}"
        )))
    }

    async fn tenant_room(
        &self,
        _: &PlanLimits,
        _: &crate::tenancy::ScopedTenant,
        _: crate::ports::limits::ResourceKind,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }

    async fn check_org_limit(
        &self,
        _: &PlanLimits,
        _: &OrganizationId,
        kind: crate::ports::limits::ResourceKind,
    ) -> Result<(), DomainError> {
        Err(DomainError::forbidden(format!(
            "plan limit reached: {kind:?}"
        )))
    }
}

/// Plan lookup that answers every tenant with one fixed plan. For tests.
pub struct FixedPlanLimits(pub PlanLimits);

#[async_trait]
impl crate::ports::limits::PlanLimitsSource for FixedPlanLimits {
    async fn for_tenant(&self, _: &TenantId) -> Result<PlanLimits, DomainError> {
        Ok(self.0.clone())
    }
}

impl Fake for Arc<dyn crate::ports::limits::LimitEnforcer> {
    fn fake() -> Self {
        Arc::new(FakeLimitEnforcer)
    }
}

impl Fake for Arc<dyn crate::ports::limits::PlanLimitsSource> {
    fn fake() -> Self {
        Arc::new(FixedPlanLimits(
            ianua_domain::domains::organization::billing::plan::OrganizationPlan::Free
                .default_limits(),
        ))
    }
}

/// Rate limiter that never limits.
pub struct NoopRateLimiter;
#[::async_trait::async_trait]
impl crate::ports::limits::RateLimiter for NoopRateLimiter {
    async fn check_and_increment(
        &self,
        _: &crate::ports::limits::RateBudget,
        limit_per_minute: u32,
    ) -> Result<u32, ianua_domain::shared::errors::DomainError> {
        Ok(limit_per_minute)
    }
}

impl Fake for Arc<dyn crate::ports::limits::RateLimiter> {
    fn fake() -> Self {
        std::sync::Arc::new(NoopRateLimiter)
    }
}

/// Mail throttle that lets every mail through.
pub struct OpenMailThrottle;
#[::async_trait::async_trait]
impl crate::ports::limits::MailThrottle for OpenMailThrottle {
    async fn admit(
        &self,
        _: crate::ports::limits::MailPurpose,
        _: &ianua_domain::types::Email,
    ) -> Result<bool, ianua_domain::shared::errors::DomainError> {
        Ok(true)
    }
}

/// Mail throttle that holds every mail back, as for an address mailed a
/// moment ago.
pub struct ShutMailThrottle;
#[::async_trait::async_trait]
impl crate::ports::limits::MailThrottle for ShutMailThrottle {
    async fn admit(
        &self,
        _: crate::ports::limits::MailPurpose,
        _: &ianua_domain::types::Email,
    ) -> Result<bool, ianua_domain::shared::errors::DomainError> {
        Ok(false)
    }
}

/// Mail throttle admitting one mail per purpose and address, as the cache
/// does within one minute, so a test sees which request spent it.
#[derive(Default)]
pub struct OneMailThrottle {
    admitted:
        std::sync::Mutex<std::collections::HashSet<(crate::ports::limits::MailPurpose, String)>>,
}

#[::async_trait::async_trait]
impl crate::ports::limits::MailThrottle for OneMailThrottle {
    async fn admit(
        &self,
        purpose: crate::ports::limits::MailPurpose,
        recipient: &ianua_domain::types::Email,
    ) -> Result<bool, DomainError> {
        let claim = (purpose, recipient.as_str().to_ascii_lowercase());
        Ok(self.admitted.lock().unwrap().insert(claim))
    }
}

impl Fake for Arc<dyn crate::ports::limits::MailThrottle> {
    fn fake() -> Self {
        std::sync::Arc::new(OpenMailThrottle)
    }
}
