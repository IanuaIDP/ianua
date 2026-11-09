//! The plan's ceilings on what a tenant keeps of its domains.

use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::limits::{LimitEnforcer, ResourceKind};

/// Refuses one more `kind` once the caller's plan has reached its ceiling on
/// it.
///
/// # Errors
///
/// - `AppError::Forbidden` when the plan has no room for another.
/// - `AppError::Internal` when the count cannot be read.
pub(super) async fn ensure_within_limit(
    limits: &dyn LimitEnforcer,
    caller: &CallerContext,
    kind: ResourceKind,
) -> Result<(), AppError> {
    limits
        .check_tenant_limit(caller.plan_limits(), &caller.tenant(), kind)
        .await
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_ctx};

    /// Acme's plan has room for another domain. Ann may add one.
    #[test]
    fn a_plan_with_room_lets_one_more_in() {
        let result = block_on(ensure_within_limit(
            &FakeLimitEnforcer,
            &test_ctx(),
            ResourceKind::Domains,
        ));

        assert!(result.is_ok());
    }

    /// A domain-limit refusal becomes forbidden for the caller requesting
    /// capacity for another domain.
    #[test]
    fn a_plan_at_its_ceiling_refuses_one_more() {
        let result = block_on(ensure_within_limit(
            &RejectingLimitEnforcer,
            &test_ctx(),
            ResourceKind::Domains,
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
