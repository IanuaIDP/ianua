//! The DataClassify stage: tags a request with the sensitivity levels the
//! tenant's classification rules define, for the upstream, later stages
//! and the request record. Acting on them is `Redact`'s job.
//!
//! It refuses only when the rules cannot be read: a request forwarded
//! untagged because the store was down would tell everyone after it that
//! nothing here is sensitive.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::data_classification::ClassificationStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::data_classification::classification::{
    ClassificationRule, ClassificationRuleSet,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::access::question::Lookup;
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::request::transform::RequestMutation;
use ianua_domain::domains::proxy::stages::decision::{HeaderEntry, StageDecision};
use ianua_domain::domains::proxy::stages::stage::ClassificationConfig;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DenialStatus, HeaderName, HeaderValue};

/// The header the forwarded request carries the levels in, highest first.
const CLASSIFICATION_HEADER: &str = "x-ianua-data-classification";

/// Tags requests with the levels the tenant's rules define, the rules
/// read within `read_timeout`.
pub(super) struct Classifier {
    store: Arc<dyn ClassificationStore>,
    read_timeout: Duration,
}

impl Classifier {
    pub(super) fn new(store: Arc<dyn ClassificationStore>, read_timeout: Duration) -> Self {
        Self {
            store,
            read_timeout,
        }
    }

    /// Tags `ctx` with the levels the tenant's rules define, and the
    /// forwarded request with them too. A tenant with no rules passes
    /// untagged; rules that cannot be read refuse.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the levels cannot be written as a
    ///   header, which every level's name can.
    pub(super) async fn classify(
        &self,
        ctx: &mut PipelineContext,
        tenant: &ScopedTenant,
        config: &ClassificationConfig,
    ) -> Result<StageDecision, DomainError> {
        let levels = match self.rule_set(tenant).await {
            Lookup::Found(rule_set) => {
                warn_on_other_rule_set(&rule_set, config);
                levels_defined(&rule_set)
            }
            Lookup::Missing => Vec::new(),
            Lookup::Unreadable => {
                return Ok(StageDecision::Deny {
                    status: DenialStatus::SERVICE_UNAVAILABLE,
                    reason: "classification_unreadable".to_owned(),
                });
            }
        };
        ctx.classification_levels.clone_from(&levels);
        let Some(header) = classification_header(&levels)? else {
            return Ok(StageDecision::Pass {
                reason: "no_classification_rules".to_owned(),
            });
        };
        Ok(StageDecision::Transform {
            mutation: RequestMutation::asserting(vec![header]),
            reason: "classified".to_owned(),
        })
    }

    /// The tenant's rule set, that it has none, or that it could not be
    /// read in time.
    async fn rule_set(
        &self,
        tenant: &ScopedTenant,
    ) -> Lookup<ClassificationRuleSet<ResolvedTenant>> {
        match tokio::time::timeout(self.read_timeout, self.store.find(tenant)).await {
            Ok(Ok(Some(rule_set))) => Lookup::Found(rule_set),
            Ok(Ok(None)) => Lookup::Missing,
            Ok(Err(error)) => {
                tracing::warn!(%error, "classification rules unreadable; refusing");
                Lookup::Unreadable
            }
            Err(_) => {
                tracing::warn!("classification rules not read in time; refusing");
                Lookup::Unreadable
            }
        }
    }
}

/// A stage set up for another rule set than the tenant's is still tagged
/// with the tenant's current one, and the drift is logged.
fn warn_on_other_rule_set(
    rule_set: &ClassificationRuleSet<ResolvedTenant>,
    config: &ClassificationConfig,
) {
    if *rule_set.id() == config.rule_set_id {
        return;
    }
    tracing::warn!(
        configured = %config.rule_set_id,
        current = %rule_set.id(),
        "the DataClassify stage names another rule set than the tenant's current one"
    );
}

/// The distinct levels `rule_set` defines, highest first.
fn levels_defined(rule_set: &ClassificationRuleSet<ResolvedTenant>) -> Vec<DataClassLevel> {
    let mut levels: Vec<DataClassLevel> = rule_set
        .rules()
        .iter()
        .map(ClassificationRule::level)
        .collect();
    levels.sort_unstable_by(|a, b| b.cmp(a));
    levels.dedup();
    levels
}

/// The header naming `levels`, or `None` when there are none.
fn classification_header(levels: &[DataClassLevel]) -> Result<Option<HeaderEntry>, DomainError> {
    if levels.is_empty() {
        return Ok(None);
    }
    let names: Vec<&str> = levels.iter().map(|level| level.as_str()).collect();
    Ok(Some(HeaderEntry::new(
        HeaderName::new(CLASSIFICATION_HEADER)?,
        HeaderValue::new(names.join(","))?,
    )))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_app::ports::TenantScoped;
    use ianua_app::test_support::data_classification::FakeClassificationStore;
    use ianua_domain::domains::data_classification::classification::RedactionStrategy;
    use ianua_domain::types::{
        ClassificationRuleSetId, CorrelationId, FieldPath, PipelineId, TenantId,
    };

    use super::*;

    fn tenant() -> ScopedTenant {
        ScopedTenant::for_test(TenantId::new())
    }

    fn ctx(tenant: &ScopedTenant) -> PipelineContext {
        PipelineContext::new(**tenant, PipelineId::new(), CorrelationId::new())
    }

    fn config() -> ClassificationConfig {
        ClassificationConfig {
            rule_set_id: ClassificationRuleSetId::new(),
        }
    }

    fn classifier(store: impl ClassificationStore + 'static) -> Classifier {
        Classifier::new(Arc::new(store), Duration::from_secs(1))
    }

    fn rule(path: &str, level: DataClassLevel) -> ClassificationRule {
        ClassificationRule::new(
            FieldPath::new(path).unwrap(),
            level,
            RedactionStrategy::Mask,
        )
    }

    #[tokio::test]
    async fn a_tenant_without_rules_passes_untagged() {
        let tenant = tenant();
        let classifier = classifier(FakeClassificationStore::empty());
        let mut ctx = ctx(&tenant);

        let decision = classifier
            .classify(&mut ctx, &tenant, &config())
            .await
            .unwrap();

        assert!(matches!(decision, StageDecision::Pass { .. }));
        assert!(ctx.classification_levels.is_empty());
    }

    /// Acme classifies an SSN as restricted and an email twice as
    /// confidential. The request carries both levels once, highest first.
    #[tokio::test]
    async fn the_levels_defined_are_tagged_highest_first() {
        let tenant = tenant();
        let store = FakeClassificationStore::with_rules(
            *tenant,
            vec![
                rule("email", DataClassLevel::Confidential),
                rule("ssn", DataClassLevel::Restricted),
                rule("contact.email", DataClassLevel::Confidential),
            ],
        );
        let classifier = classifier(store);
        let mut ctx = ctx(&tenant);

        let decision = classifier
            .classify(&mut ctx, &tenant, &config())
            .await
            .unwrap();

        let StageDecision::Transform { mutation, .. } = decision else {
            panic!("classified rules tag the request");
        };
        let header = &mutation.headers_to_set()[0];
        assert_eq!(header.name().as_str(), CLASSIFICATION_HEADER);
        assert_eq!(header.value().as_str(), "restricted,confidential");
        assert_eq!(
            ctx.classification_levels,
            vec![DataClassLevel::Restricted, DataClassLevel::Confidential]
        );
    }

    /// A classification store error produces a 503 denial.
    #[tokio::test]
    async fn unreadable_rules_refuse() {
        let tenant = tenant();
        let classifier = classifier(Unreadable);
        let mut ctx = ctx(&tenant);

        let decision = classifier
            .classify(&mut ctx, &tenant, &config())
            .await
            .unwrap();

        assert!(matches!(
            decision,
            StageDecision::Deny { status, .. } if status == DenialStatus::SERVICE_UNAVAILABLE
        ));
    }

    struct Unreadable;

    impl TenantScoped for Unreadable {}

    #[async_trait]
    impl ClassificationStore for Unreadable {
        async fn find(
            &self,
            _tenant_id: &ScopedTenant,
        ) -> Result<Option<ClassificationRuleSet<ResolvedTenant>>, DomainError> {
            Err(DomainError::infra_msg("the store is down"))
        }

        async fn save(
            &self,
            _tenant_id: &ScopedTenant,
            _rule_set: &ClassificationRuleSet<ResolvedTenant>,
        ) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("the store is down"))
        }
    }
}
