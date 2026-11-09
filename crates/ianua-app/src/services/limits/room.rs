//! The plan check every create in a tenant makes before it adds a counted
//! resource.

use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::limits::{LimitEnforcer, PlanLimitsSource, ResourceKind};
use crate::tenancy::ScopedTenant;

/// Refuses one more `kind` in the caller's tenant when its plan allows no
/// more.
///
/// # Errors
///
/// - `AppError::Domain` when the plan's limit for `kind` is reached.
/// - `AppError::Domain` when the count cannot be read.
pub(crate) async fn ensure_room_in_tenant(
    enforcer: &dyn LimitEnforcer,
    caller: &CallerContext,
    kind: ResourceKind,
) -> Result<(), AppError> {
    enforcer
        .check_tenant_limit(caller.plan_limits(), &caller.tenant(), kind)
        .await
        .map_err(AppError::from_domain)
}

/// Where a tenant's plan and its use of it are read, for work no request
/// brought the plan to: the gateway's questions, a worker's job.
#[derive(Clone, Copy)]
pub(crate) struct PlanRoom<'a> {
    /// Reads the tenant's plan.
    pub(crate) plans: &'a dyn PlanLimitsSource,
    /// Counts what the tenant holds against it.
    pub(crate) limits: &'a dyn LimitEnforcer,
}

/// Ports that read a tenant's plan and count what it holds against it, so
/// a use case no request brought the plan to can make its check.
pub(crate) trait PlanSources {
    /// Reads the tenant's plan.
    fn plan_limits(&self) -> &dyn PlanLimitsSource;

    /// Counts what the tenant holds against its plan.
    fn limit_enforcer(&self) -> &dyn LimitEnforcer;

    /// Where the tenant's plan and its use of it are read.
    fn plan_room(&self) -> PlanRoom<'_> {
        PlanRoom {
            plans: self.plan_limits(),
            limits: self.limit_enforcer(),
        }
    }
}

/// Refuses one more `kind` in `tenant` when its plan, read for it, allows
/// no more.
///
/// # Errors
///
/// - `AppError::Forbidden` when the plan's limit for `kind` is reached.
/// - `AppError::NotFound` when the tenant or its organization is gone: a
///   tenant whose plan cannot be read gets no allowance.
/// - `AppError::Internal` when the plan or the count cannot be read.
pub(crate) async fn ensure_room_for_tenant(
    room: PlanRoom<'_>,
    tenant: &ScopedTenant,
    kind: ResourceKind,
) -> Result<(), AppError> {
    let plan = room
        .plans
        .for_tenant(tenant)
        .await
        .map_err(AppError::from_domain)?;
    room.limits
        .check_tenant_limit(&plan, tenant, kind)
        .await
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{
        Fake, FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_ctx,
    };

    fn room_under(limits: &dyn LimitEnforcer) -> Result<(), AppError> {
        let plans: Arc<dyn PlanLimitsSource> = Fake::fake();
        let room = PlanRoom {
            plans: plans.as_ref(),
            limits,
        };
        block_on(ensure_room_for_tenant(
            room,
            &test_ctx().tenant(),
            ResourceKind::PendingApprovals,
        ))
    }

    /// Acme's plan has room for another open approval.
    #[test]
    fn a_tenant_below_its_plans_limit_has_room() {
        assert!(room_under(&FakeLimitEnforcer).is_ok());
    }

    /// Acme holds as many open approvals as its plan allows. One more is
    /// refused.
    #[test]
    fn a_tenant_at_its_plans_limit_is_refused() {
        let refused = room_under(&RejectingLimitEnforcer);

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
    }
}
