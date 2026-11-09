//! Change classification rule: say again how sensitive a classified field
//! is and how the proxy redacts it, keeping the rule's id and field.

use std::sync::Arc;

use ianua_domain::domains::data_classification::classification::RedactionStrategy;
use ianua_domain::domains::data_classification::control::ClassificationControlCheck;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ClassificationRuleId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::data_classification::ClassificationStore;
use crate::use_case::Command;
use crate::use_cases::data_classification::lookup::{existing_rule, existing_rule_set};

/// The ports [`ChangeClassificationRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeClassificationRulePorts {
    /// The tenant's rule set.
    pub store: Arc<dyn ClassificationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which rule to change, and what it says from now on.
pub struct ChangeClassificationRuleRequest {
    /// The rule to change.
    pub rule_id: ClassificationRuleId,
    /// How sensitive its field is.
    pub level: DataClassLevel,
    /// What the proxy does to its field once it is above the threshold.
    pub redaction: RedactionStrategy,
}

/// Changes a rule in the tenant's classification rule set.
pub struct ChangeClassificationRuleUseCase {
    ports: ChangeClassificationRulePorts,
}

impl ChangeClassificationRuleUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ChangeClassificationRulePorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeClassificationRuleUseCase {
    type Caller = CallerContext;
    type Input = ChangeClassificationRuleRequest;
    type Output = Result<(), AppError>;

    /// Changes the level and redaction of `request.rule_id` in place and
    /// records `proxy.classification_rule_changed`. The field is never
    /// left unredacted between the two, as removing and adding again
    /// would leave it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change classification
    ///   rules.
    /// - `AppError::NotFound` if the rule set or rule doesn't exist.
    /// - `AppError::Domain` carrying `DomainError::Validation` for the
    ///   `Encrypt` strategy, which the rule set refuses.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeClassificationRuleRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ClassificationControlCheck::ensure_may_change_rules(&authority)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut rule_set = existing_rule_set(self.ports.store.as_ref(), &tenant).await?;
        existing_rule(&rule_set, &request.rule_id)?;
        rule_set
            .change_rule(
                &request.rule_id,
                request.level,
                request.redaction,
                &authority,
            )
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
    use ianua_domain::domains::data_classification::classification::ClassificationRule;
    use ianua_domain::types::FieldPath;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::data_classification::FakeClassificationStore;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: ChangeClassificationRuleUseCase,
        store: Arc<FakeClassificationStore>,
        audit: Arc<FakeEventDispatcher>,
        rule_id: ClassificationRuleId,
    }

    impl Setup {
        fn with(authorities: FakeTenantAuthorities) -> Self {
            let rule = ClassificationRule::new(
                FieldPath::new("user.ssn").unwrap(),
                DataClassLevel::Confidential,
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
                uc: ChangeClassificationRuleUseCase::new(ChangeClassificationRulePorts {
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

        fn change_as(
            &self,
            ctx: &CallerContext,
            request: ChangeClassificationRuleRequest,
        ) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(ctx, &test_auditor(self.audit.clone()), request),
            )
        }

        fn change(&self, request: ChangeClassificationRuleRequest) -> Result<(), AppError> {
            self.change_as(&test_ctx(), request)
        }

        fn to_restricted_removal(&self) -> ChangeClassificationRuleRequest {
            ChangeClassificationRuleRequest {
                rule_id: self.rule_id,
                level: DataClassLevel::Restricted,
                redaction: RedactionStrategy::Remove,
            }
        }

        fn rules(&self) -> Vec<ClassificationRule> {
            self.store.rules_of(&test_ctx().tenant_id())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Fay decides `user.ssn` is restricted and must be removed, not
    /// masked. The rule keeps its id and field and says so from now on.
    #[test]
    fn a_rule_is_changed_in_place() {
        let setup = Setup::new();

        setup.change(setup.to_restricted_removal()).unwrap();

        let rules = setup.rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(*rules[0].id(), setup.rule_id);
        assert_eq!(rules[0].field_path().as_str(), "user.ssn");
        assert_eq!(rules[0].level(), DataClassLevel::Restricted);
        assert!(matches!(rules[0].redaction(), RedactionStrategy::Remove));
    }

    /// Fay's change is recorded.
    #[test]
    fn changing_a_rule_is_recorded() {
        let setup = Setup::new();

        setup.change(setup.to_restricted_removal()).unwrap();

        assert_eq!(setup.recorded(), vec!["proxy.classification_rule_changed"]);
    }

    /// Fay asks to encrypt `user.ssn`, which nothing carries out yet. The
    /// change is refused, the rule still masks, and nothing is recorded.
    #[test]
    fn a_change_to_encryption_is_refused() {
        let setup = Setup::new();

        let result = setup.change(ChangeClassificationRuleRequest {
            redaction: RedactionStrategy::Encrypt,
            ..setup.to_restricted_removal()
        });

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(matches!(
            setup.rules()[0].redaction(),
            RedactionStrategy::Mask
        ));
        assert!(setup.recorded().is_empty());
    }

    /// Fay names a rule Acme does not have. It is not found and nothing is
    /// recorded.
    #[test]
    fn an_unknown_rule_is_not_found() {
        let setup = Setup::new();

        let result = setup.change(ChangeClassificationRuleRequest {
            rule_id: ClassificationRuleId::new(),
            ..setup.to_restricted_removal()
        });

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Acme never classified anything. Changing a rule is not found.
    #[test]
    fn a_change_without_a_rule_set_is_not_found() {
        let setup = Setup::over(
            Arc::new(FakeClassificationStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            ClassificationRuleId::new(),
        );

        let result = setup.change(setup.to_restricted_removal());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Without the update right, lowering `user.ssn` to public is forbidden
    /// and its classification remains confidential.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::with(FakeTenantAuthorities::holding(&[]));

        let result = setup.change(ChangeClassificationRuleRequest {
            level: DataClassLevel::Public,
            ..setup.to_restricted_removal()
        });

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.rules()[0].level(), DataClassLevel::Confidential);
    }

    /// Without the update right, changing an unknown rule is forbidden
    /// rather than disclosing whether the rule exists.
    #[test]
    fn a_caller_without_the_update_right_is_refused_for_an_unknown_rule() {
        let setup = Setup::with(FakeTenantAuthorities::holding(&[]));

        let result = setup.change(ChangeClassificationRuleRequest {
            rule_id: ClassificationRuleId::new(),
            ..setup.to_restricted_removal()
        });

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot change a classification rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.change(setup.to_restricted_removal());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot change a tenant's
    /// rule, and its classification remains confidential.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::new();

        let result = setup.change_as(&operator_without_grant(), setup.to_restricted_removal());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.rules()[0].level(), DataClassLevel::Confidential);
    }
}
