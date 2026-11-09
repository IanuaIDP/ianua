//! Remove classification rule: stop treating a response field as sensitive.

use std::sync::Arc;

use ianua_domain::domains::data_classification::control::ClassificationControlCheck;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ClassificationRuleId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::data_classification::ClassificationStore;
use crate::use_case::Command;
use crate::use_cases::data_classification::lookup::{existing_rule, existing_rule_set};

/// The ports [`RemoveClassificationRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveClassificationRulePorts {
    /// The tenant's rule set.
    pub store: Arc<dyn ClassificationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a rule from the tenant's classification rule set.
pub struct RemoveClassificationRuleUseCase {
    ports: RemoveClassificationRulePorts,
}

impl RemoveClassificationRuleUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RemoveClassificationRulePorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveClassificationRuleUseCase {
    type Caller = CallerContext;
    type Input = ClassificationRuleId;
    type Output = Result<(), AppError>;

    /// Removes the rule `rule_id` and records
    /// `proxy.classification_rule_removed`. The field it classified then
    /// reaches callers unredacted.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change classification
    ///   rules.
    /// - `AppError::NotFound` if the rule set or rule doesn't exist.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        rule_id: ClassificationRuleId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ClassificationControlCheck::ensure_may_change_rules(&authority)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut rule_set = existing_rule_set(self.ports.store.as_ref(), &tenant).await?;
        existing_rule(&rule_set, &rule_id)?;
        rule_set
            .remove_rule(&rule_id, &authority)
            .map_err(AppError::from_domain)?;
        self.ports
            .store
            .save(&tenant, &rule_set)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), rule_set.take_events(&tenant))
            .await
            .or_internal()
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
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: RemoveClassificationRuleUseCase,
        store: Arc<FakeClassificationStore>,
        audit: Arc<FakeEventDispatcher>,
        rule_id: ClassificationRuleId,
    }

    impl Setup {
        fn with(authorities: FakeTenantAuthorities) -> Self {
            let rule = ClassificationRule::new(
                FieldPath::new("user.ssn").unwrap(),
                DataClassLevel::Restricted,
                RedactionStrategy::Mask,
            );
            let rule_id = *rule.id();
            let store = Arc::new(FakeClassificationStore::with_rules(
                test_ctx().tenant_id(),
                vec![rule],
            ));
            Self::over(store, authorities, rule_id)
        }

        fn over(
            store: Arc<FakeClassificationStore>,
            authorities: FakeTenantAuthorities,
            rule_id: ClassificationRuleId,
        ) -> Self {
            Self {
                uc: RemoveClassificationRuleUseCase::new(RemoveClassificationRulePorts {
                    store: store.clone(),
                    tenant_authorities: Arc::new(authorities),
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
                rule_id,
            }
        }

        fn new() -> Self {
            Self::with(FakeTenantAuthorities::holding_everything())
        }

        fn remove_as(
            &self,
            ctx: &CallerContext,
            rule_id: ClassificationRuleId,
        ) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(ctx, &test_auditor(self.audit.clone()), rule_id),
            )
        }

        fn remove(&self, rule_id: ClassificationRuleId) -> Result<(), AppError> {
            self.remove_as(&test_ctx(), rule_id)
        }

        fn rules(&self) -> Vec<ClassificationRule> {
            self.store.rules_of(&test_ctx().tenant_id())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Fay removes the rule masking `user.ssn`. Acme's set has no rules left.
    #[test]
    fn remove_existing_rule() {
        let setup = Setup::new();

        setup.remove(setup.rule_id).unwrap();

        assert!(setup.rules().is_empty());
    }

    /// Fay's removal is recorded.
    #[test]
    fn removing_a_rule_is_recorded() {
        let setup = Setup::new();

        setup.remove(setup.rule_id).unwrap();

        assert_eq!(setup.recorded(), vec!["proxy.classification_rule_removed"]);
    }

    /// Fay names a rule Acme does not have. It is not found and nothing is
    /// recorded.
    #[test]
    fn remove_nonexistent_rule_returns_not_found() {
        let setup = Setup::new();

        let result = setup.remove(ClassificationRuleId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Acme never classified anything. Removing a rule is not found.
    #[test]
    fn remove_without_rule_set_returns_not_found() {
        let setup = Setup::over(
            Arc::new(FakeClassificationStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            ClassificationRuleId::new(),
        );

        let result = setup.remove(setup.rule_id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Without the update right, removing the rule for `user.ssn` is
    /// forbidden and the rule remains in the set.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::with(FakeTenantAuthorities::holding(&[]));

        let result = setup.remove(setup.rule_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.rules().len(), 1);
    }

    /// Without the update right, removing an unknown rule is forbidden
    /// rather than disclosing whether the rule exists.
    #[test]
    fn a_caller_without_the_update_right_is_refused_for_an_unknown_rule() {
        let setup = Setup::with(FakeTenantAuthorities::holding(&[]));

        let result = setup.remove(ClassificationRuleId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot remove a classification rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.remove(setup.rule_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot remove a tenant's
    /// classification rule, which remains in the set.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::new();

        let result = setup.remove_as(&operator_without_grant(), setup.rule_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.rules().len(), 1);
    }
}
