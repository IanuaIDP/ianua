//! Get classification: the tenant's data classification rules.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ClassificationAction, SystemPermission};
use ianua_domain::domains::data_classification::classification::ClassificationRuleSet;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::data_classification::ClassificationStore;
use crate::use_case::Query;
use crate::use_cases::data_classification::lookup::saved_rule_set;

/// The ports [`GetClassificationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetClassificationPorts {
    /// The tenant's rule set.
    pub store: Arc<dyn ClassificationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the tenant's classification rule set.
pub struct GetClassificationUseCase {
    ports: GetClassificationPorts,
}

impl GetClassificationUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetClassificationPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetClassificationUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Option<ClassificationRuleSet<ResolvedTenant>>, AppError>;

    /// The tenant's rule set, or `None` when it has classified nothing yet.
    ///
    /// Having no rules yet is a normal state, not a missing resource: the
    /// set is made with the first rule, by someone who may change rules, so
    /// a reader is shown that there are none rather than refused.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view classification
    ///   rules.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Option<ClassificationRuleSet<ResolvedTenant>>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Classification(ClassificationAction::View))
            .map_err(AppError::from_domain)?;
        saved_rule_set(self.ports.store.as_ref(), &ctx.tenant()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::classification::{
        ClassificationRule, RedactionStrategy,
    };
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::types::FieldPath;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::data_classification::FakeClassificationStore;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{block_on, test_ctx};

    fn ssn_masked() -> Arc<FakeClassificationStore> {
        Arc::new(FakeClassificationStore::with_rules(
            test_ctx().tenant_id(),
            vec![ClassificationRule::new(
                FieldPath::new("user.ssn").unwrap(),
                DataClassLevel::Restricted,
                RedactionStrategy::Mask,
            )],
        ))
    }

    fn reading(store: Arc<FakeClassificationStore>) -> GetClassificationUseCase {
        GetClassificationUseCase::new(GetClassificationPorts {
            store,
            ..GetClassificationPorts::fakes()
        })
    }

    fn refusing(authorities: FakeTenantAuthorities) -> GetClassificationUseCase {
        GetClassificationUseCase::new(GetClassificationPorts {
            store: ssn_masked(),
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// Acme masks `user.ssn`. Ann sees that one rule.
    #[test]
    fn returns_existing_rule_set() {
        let uc = reading(ssn_masked());

        let result = block_on(uc.execute(&test_ctx(), ())).unwrap().unwrap();

        assert_eq!(result.rules().len(), 1);
    }

    /// Acme has classified nothing yet. Ann is told there is no rule set,
    /// rather than refused as if something were missing.
    #[test]
    fn a_tenant_that_has_classified_nothing_has_no_rule_set() {
        let uc = reading(Arc::new(FakeClassificationStore::empty()));

        let result = block_on(uc.execute(&test_ctx(), ())).unwrap();

        assert!(result.is_none());
    }

    /// Reading the tenant's classification rules requires the view right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let uc = refusing(FakeTenantAuthorities::holding(&[]));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's classification rules.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = refusing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot read a tenant's
    /// classification rules.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let uc = reading(ssn_masked());

        let result = block_on(uc.execute(&operator_without_grant(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
