//! List separation rules: every pair of roles the tenant keeps apart.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::separation::SeparationRule;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::SeparationRuleStore;
use crate::use_case::Query;

/// The ports [`ListRulesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListRulesPorts {
    /// Lists the rules.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the separation-of-duties rules of the caller's tenant.
pub struct ListRulesUseCase {
    ports: ListRulesPorts,
}

impl ListRulesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListRulesPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListRulesUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<SeparationRule<ResolvedTenant>>, AppError>;

    /// Every rule of the tenant, oldest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<SeparationRule<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .separation_rules
            .list(&ctx.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        FakeSeparationRuleStore, separation_between, stored_role,
    };
    use crate::test_support::{block_on, test_ctx};

    fn one_rule() -> ListRulesPorts {
        let raiser = stored_role("raiser", Vec::new(), Vec::new());
        let approver = stored_role("approver", Vec::new(), Vec::new());
        let rule = separation_between("raise or approve payments", &raiser, &approver);
        ListRulesPorts {
            separation_rules: Arc::new(FakeSeparationRuleStore::holding(
                test_ctx().tenant_id(),
                [rule],
            )),
            ..ListRulesPorts::fakes()
        }
    }

    fn list(ports: ListRulesPorts) -> Result<Vec<SeparationRule<ResolvedTenant>>, AppError> {
        block_on(ListRulesUseCase::new(ports).execute(&test_ctx(), ()))
    }

    /// Ann lists the rules and sees raising and approving kept apart.
    #[test]
    fn the_rules_are_listed() {
        let rules = list(one_rule()).unwrap();

        assert_eq!(rules[0].name().as_str(), "raise or approve payments");
    }

    /// Separation rules cannot be listed without permission to view roles.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let ports = ListRulesPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..one_rule()
        };

        assert!(matches!(list(ports), Err(AppError::Forbidden(_))));
    }

    /// Listing separation rules rejects a signed-out session as unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListRulesPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..one_rule()
        };

        assert!(matches!(list(ports), Err(AppError::Unauthenticated)));
    }
}
