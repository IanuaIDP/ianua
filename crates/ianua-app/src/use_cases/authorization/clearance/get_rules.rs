//! Get clearance rules: which of the tenant's app permissions clear their
//! holders for confidential or restricted data.

use std::sync::Arc;

use ianua_domain::domains::authorization::clearance::ClearanceRules;
use ianua_domain::domains::authorization::permission::{ClassificationAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::ClearanceRuleStore;
use crate::use_case::Query;
use crate::use_cases::authorization::clearance::lookup::current_rules;

/// The ports [`GetRulesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetRulesPorts {
    /// Loads the rules.
    pub clearance_rules: Arc<dyn ClearanceRuleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the clearance rules of the caller's tenant.
pub struct GetRulesUseCase {
    ports: GetRulesPorts,
}

impl GetRulesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetRulesPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetRulesUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<ClearanceRules<ResolvedTenant>, AppError>;

    /// The tenant's clearance rules; none when nobody wrote one.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view classification
    ///   rules.
    /// - `AppError::Internal` when the rules cannot be read.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<ClearanceRules<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Classification(ClassificationAction::View))
            .map_err(AppError::from_domain)?;
        current_rules(self.ports.clearance_rules.as_ref(), &ctx.tenant()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::{block_on, test_ctx};

    fn get(ports: GetRulesPorts) -> Result<ClearanceRules<ResolvedTenant>, AppError> {
        block_on(GetRulesUseCase::new(ports).execute(&test_ctx(), ()))
    }

    /// Ann's tenant never wrote a clearance rule. She reads none, not an
    /// error.
    #[test]
    fn a_tenant_without_rules_reads_none() {
        let rules = get(GetRulesPorts::fakes()).unwrap();

        assert!(rules.rules().is_empty());
    }

    /// Reading clearance rules is forbidden without classification view permission.
    #[test]
    fn a_caller_who_may_not_view_classification_is_refused() {
        let ports = GetRulesPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..GetRulesPorts::fakes()
        };

        assert!(matches!(get(ports), Err(AppError::Forbidden(_))));
    }

    /// Reading clearance rules rejects a signed-out session as unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = GetRulesPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..GetRulesPorts::fakes()
        };

        assert!(matches!(get(ports), Err(AppError::Unauthenticated)));
    }
}
