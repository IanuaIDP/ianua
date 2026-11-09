//! Add classification rule: mark a response field as sensitive so the
//! proxy redacts it.

use std::sync::Arc;

use ianua_domain::domains::data_classification::classification::{
    ClassificationRule, RedactionStrategy,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ClassificationRuleId, FieldPath};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::data_classification::ClassificationStore;
use crate::use_case::Command;
use crate::use_cases::data_classification::lookup::current_rule_set;

/// The ports [`AddClassificationRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddClassificationRulePorts {
    /// The tenant's rule set.
    pub store: Arc<dyn ClassificationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which field to classify, how sensitive it is, and how to redact it.
pub struct AddClassificationRuleRequest {
    /// The dot-notation path of the field.
    pub field_path: FieldPath,
    /// How sensitive the field is.
    pub level: DataClassLevel,
    /// What the proxy does to the field once it is above the threshold.
    pub redaction: RedactionStrategy,
}

/// Adds a rule to the tenant's classification rule set.
pub struct AddClassificationRuleUseCase {
    ports: AddClassificationRulePorts,
}

impl AddClassificationRuleUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: AddClassificationRulePorts) -> Self {
        Self { ports }
    }
}

impl Command for AddClassificationRuleUseCase {
    type Caller = CallerContext;
    type Input = AddClassificationRuleRequest;
    type Output = Result<ClassificationRuleId, AppError>;

    /// Adds a classification rule to the tenant's rule set, making the set
    /// with the first rule, records `proxy.classification_rule_added`, and
    /// returns the rule's id.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change classification
    ///   rules.
    /// - `AppError::Domain` carrying `DomainError::Validation` for the
    ///   `Encrypt` strategy, which the rule set refuses.
    /// - `AppError::Conflict` if a rule already classifies this field path.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: AddClassificationRuleRequest,
    ) -> Result<ClassificationRuleId, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let tenant = ctx.tenant();
        let mut rule_set = current_rule_set(self.ports.store.as_ref(), &tenant, &authority).await?;
        let rule = ClassificationRule::new(request.field_path, request.level, request.redaction);
        let rule_id = rule_set
            .add_rule(rule, &authority)
            .map_err(AppError::from_domain)?;
        self.ports
            .store
            .save(&tenant, &rule_set)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), rule_set.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(rule_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::data_classification::FakeClassificationStore;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: AddClassificationRuleUseCase,
        store: Arc<FakeClassificationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(authorities: FakeTenantAuthorities) -> Self {
            let store = Arc::new(FakeClassificationStore::empty());
            Self {
                uc: AddClassificationRuleUseCase::new(AddClassificationRulePorts {
                    store: store.clone(),
                    tenant_authorities: Arc::new(authorities),
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::with(FakeTenantAuthorities::holding_everything())
        }

        fn add_as(
            &self,
            ctx: &CallerContext,
            request: AddClassificationRuleRequest,
        ) -> Result<ClassificationRuleId, AppError> {
            block_on(
                self.uc
                    .execute(ctx, &test_auditor(self.audit.clone()), request),
            )
        }

        fn add(
            &self,
            request: AddClassificationRuleRequest,
        ) -> Result<ClassificationRuleId, AppError> {
            self.add_as(&test_ctx(), request)
        }

        fn rules(&self) -> Vec<ClassificationRule> {
            self.store.rules_of(&test_ctx().tenant_id())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn rule(
        path: &str,
        level: DataClassLevel,
        redaction: RedactionStrategy,
    ) -> AddClassificationRuleRequest {
        AddClassificationRuleRequest {
            field_path: FieldPath::new(path).unwrap(),
            level,
            redaction,
        }
    }

    fn mask_ssn() -> AddClassificationRuleRequest {
        rule(
            "user.ssn",
            DataClassLevel::Restricted,
            RedactionStrategy::Mask,
        )
    }

    fn encrypt_ssn() -> AddClassificationRuleRequest {
        rule(
            "user.ssn",
            DataClassLevel::Restricted,
            RedactionStrategy::Encrypt,
        )
    }

    /// Fay asks to encrypt `user.ssn`, which nothing carries out yet. The
    /// rule is refused rather than stored as a promise the proxy breaks, and
    /// nothing is recorded.
    #[test]
    fn a_rule_that_would_encrypt_is_refused() {
        let setup = Setup::new();

        let result = setup.add(encrypt_ssn());

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(setup.recorded().is_empty());
    }

    /// Acme has classified nothing yet. Fay's first rule makes the set and
    /// is saved in it.
    #[test]
    fn add_rule_creates_rule_set_if_empty() {
        let setup = Setup::new();

        setup.add(mask_ssn()).unwrap();

        let rules = setup.rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].field_path().as_str(), "user.ssn");
    }

    /// Fay classifies two different fields. Both rules are kept.
    #[test]
    fn add_multiple_rules() {
        let setup = Setup::new();
        setup.add(mask_ssn()).unwrap();

        setup
            .add(rule(
                "user.email",
                DataClassLevel::Confidential,
                RedactionStrategy::Hash,
            ))
            .unwrap();

        assert_eq!(setup.rules().len(), 2);
    }

    /// Fay masks `user.ssn`, then tags it public. The second rule would
    /// never apply, so it is refused as a conflict and not kept.
    #[test]
    fn a_second_rule_on_the_same_field_is_refused() {
        let setup = Setup::new();
        setup.add(mask_ssn()).unwrap();

        let second = setup.add(rule(
            "user.ssn",
            DataClassLevel::Public,
            RedactionStrategy::Remove,
        ));

        assert!(matches!(second, Err(AppError::Conflict(_))));
        assert_eq!(setup.rules().len(), 1);
    }

    /// The id handed back is the id of the rule that was saved.
    #[test]
    fn adding_returns_the_id_of_the_new_rule() {
        let setup = Setup::new();

        let id = setup.add(mask_ssn()).unwrap();

        assert_eq!(*setup.rules()[0].id(), id);
    }

    /// Fay's new rule is recorded.
    #[test]
    fn adding_a_rule_is_recorded() {
        let setup = Setup::new();

        setup.add(mask_ssn()).unwrap();

        assert_eq!(setup.recorded(), vec!["proxy.classification_rule_added"]);
    }

    /// Without the update right, adding a rule to mask `user.ssn` is
    /// forbidden and leaves the tenant without rules.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::with(FakeTenantAuthorities::holding(&[]));

        let result = setup.add(mask_ssn());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.rules().is_empty());
    }

    /// A signed-out session cannot add a classification rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.add(mask_ssn());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot add a tenant's
    /// classification rule, and no rule is saved.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::new();

        let result = setup.add_as(&operator_without_grant(), mask_ssn());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.rules().is_empty());
    }
}
