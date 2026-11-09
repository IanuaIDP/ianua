//! Holding a tenant to its plan before a new account is opened, which every
//! path that opens one asks first.

use ianua_domain::domains::organization::billing::plan::PlanLimits;

use crate::error::AppError;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::tenancy::ScopedTenant;

/// Refuses opening one more `kind` in `tenant` when `plan` has no room.
///
/// # Errors
///
/// - `AppError::Forbidden` when the plan's limit is reached.
/// - `AppError::Internal` when the count cannot be read.
pub(in crate::use_cases::identity) async fn ensure_room(
    limits: &dyn LimitEnforcer,
    tenant: &ScopedTenant,
    plan: &PlanLimits,
    kind: ResourceKind,
) -> Result<(), AppError> {
    limits
        .check_tenant_limit(plan, tenant, kind)
        .await
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_ctx};

    fn room_under(limits: &dyn LimitEnforcer) -> Result<(), AppError> {
        let ctx = test_ctx();
        block_on(ensure_room(
            limits,
            &ctx.tenant(),
            ctx.plan_limits(),
            ResourceKind::Users,
        ))
    }

    /// The tenant's plan has room. Opening another account goes ahead.
    #[test]
    fn a_plan_with_room_lets_the_account_open() {
        assert!(room_under(&FakeLimitEnforcer).is_ok());
    }

    /// The tenant is at its plan's user limit. Opening another account is
    /// refused.
    #[test]
    fn a_full_plan_refuses_the_account() {
        assert!(matches!(
            room_under(&RejectingLimitEnforcer),
            Err(AppError::Forbidden(_))
        ));
    }
}
