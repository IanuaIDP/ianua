//! Add stage: add a new stage to the end of one of the tenant's pipelines.

use std::sync::Arc;

use ianua_domain::domains::proxy::stages::stage::{StageConfig, StageKind, StageRemoval};
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::types::PipelineId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::data_classification::ClassificationStore;
use crate::ports::proxy::PipelineStore;
use crate::services::routing::rule_sets::ensure_reads_own_rules;
use crate::use_case::Command;
use crate::use_cases::proxy::pipeline_changes::PipelineChange;

/// Which pipeline gets which new stage.
pub struct AddRequest {
    /// The pipeline the stage is appended to.
    pub pipeline_id: PipelineId,
    /// What the new stage does.
    pub kind: StageKind,
}

/// The ports [`AddUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddPorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// Where the tenant's classification rules are kept, which a stage
    /// reading rules must name.
    pub classification_store: Arc<dyn ClassificationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Adds a stage to a pipeline.
pub struct AddUseCase {
    ports: AddPorts,
}

impl AddUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AddPorts) -> Self {
        Self { ports }
    }
}

impl Command for AddUseCase {
    type Caller = CallerContext;
    type Input = AddRequest;
    type Output = Result<(), AppError>;

    /// Adds a stage to the end of the pipeline and records
    /// `proxy.stage_added`, with the position the stage took.
    ///
    /// It takes no position. The pipeline appends, because only it knows
    /// what is already there, and a caller that guesses low puts the stage
    /// ahead of Identity, filtering traffic before anyone knows who sent it.
    /// Reorder afterwards to move it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change pipelines, or
    ///   the pipeline is active.
    /// - `AppError::NotFound` when the tenant has no such pipeline.
    /// - `AppError::Domain` when the stage is set up so it could not do its
    ///   job, reads classification rules that are not the tenant's, or is an
    ///   Identity or Policy stage.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: AddRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::ChangePipeline)
            .map_err(AppError::from_domain)?;
        ensure_reads_own_rules(
            self.ports.classification_store.as_ref(),
            &caller.tenant(),
            [&request.kind],
        )
        .await?;
        let removal = StageRemoval::of(&request.kind);
        let stage = StageConfig::new(request.kind, 0, removal).map_err(AppError::from_domain)?;
        PipelineChange::by(caller, auditor)
            .pipeline(
                self.ports.pipeline_store.as_ref(),
                &request.pipeline_id,
                |pipeline| pipeline.add_stage(stage, &control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::proxy::stages::stage::RedactConfig;
    use ianua_domain::types::{ClassificationRuleSetId, TenantId};

    use super::*;
    use crate::tenancy::ScopedTenant;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::data_classification::FakeClassificationStore;
    use crate::test_support::proxy::{
        FakePipelineStore, rate_limit_stage, test_pipeline_id, test_pipeline_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann adds `kind` to a draft pipeline of a tenant whose rules
    /// `classification` keeps, and what the pipeline then holds.
    fn add_reading(
        classification: FakeClassificationStore,
        kind: StageKind,
    ) -> (Result<(), AppError>, usize) {
        let store = seeded(PipelineStatus::Draft);
        let use_case = AddUseCase::new(AddPorts {
            pipeline_store: store.clone(),
            classification_store: Arc::new(classification),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        let request = AddRequest {
            pipeline_id: test_pipeline_id(),
            kind,
        };
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit), request));
        (result, stage_count(&store))
    }

    /// A Redact stage over `rule_set`, hiding confidential fields.
    fn redacting(rule_set: ClassificationRuleSetId) -> StageKind {
        StageKind::Redact(RedactConfig {
            rule_set_id: rule_set,
            min_class: DataClassLevel::Confidential,
        })
    }

    /// The store holding rules for `tenant`, and their id.
    fn classified(tenant: TenantId) -> (FakeClassificationStore, ClassificationRuleSetId) {
        let store = FakeClassificationStore::with_rules(tenant, vec![]);
        let id = *block_on(store.find(&ScopedTenant::for_test(tenant)))
            .unwrap()
            .unwrap()
            .id();
        (store, id)
    }

    /// Ann adds a Redact stage reading her tenant's own rules. It is added.
    #[test]
    fn a_redact_stage_reading_the_tenants_rules_is_added() {
        let (classification, own) = classified(test_ctx().tenant_id());

        let (result, stages) = add_reading(classification, redacting(own));

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(stages, 3);
    }

    /// A Redact stage naming another tenant's rules is refused, leaving the
    /// pipeline with its two original stages.
    #[test]
    fn a_redact_stage_reading_another_tenants_rules_is_refused() {
        let (classification, _) = classified(test_ctx().tenant_id());
        let (_, bobs) = classified(TenantId::new());

        let (result, stages) = add_reading(classification, redacting(bobs));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(stages, 2);
    }

    /// A tenant without classification rules cannot add a Redact stage; the
    /// pipeline's stage count stays at two.
    #[test]
    fn a_redact_stage_in_an_unclassified_tenant_is_refused() {
        let (result, stages) = add_reading(
            FakeClassificationStore::empty(),
            redacting(ClassificationRuleSetId::new()),
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(stages, 2);
    }

    fn seeded(status: PipelineStatus) -> Arc<FakePipelineStore> {
        Arc::new(FakePipelineStore::holding(
            test_ctx().tenant_id(),
            test_pipeline_in(status),
        ))
    }

    fn add(
        store: &Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        kind: StageKind,
    ) -> Result<(), AppError> {
        let use_case = AddUseCase::new(AddPorts {
            pipeline_store: store.clone(),
            classification_store: Arc::new(FakeClassificationStore::empty()),
            tenant_authorities: Arc::new(authorities),
        });
        let request = AddRequest {
            pipeline_id: test_pipeline_id(),
            kind,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn rate_limit() -> StageKind {
        rate_limit_stage(0).kind().clone()
    }

    fn stage_count(store: &FakePipelineStore) -> usize {
        block_on(store.find(&test_ctx().tenant(), &test_pipeline_id()))
            .unwrap()
            .unwrap()
            .stages()
            .len()
    }

    /// Ann adds a rate limit to a draft pipeline. It runs after Identity
    /// and Policy, and the addition is recorded.
    #[test]
    fn a_stage_is_appended_after_the_mandatory_ones() {
        let store = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        add(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            rate_limit(),
        )
        .unwrap();

        let pipeline = block_on(store.find(&test_ctx().tenant(), &test_pipeline_id()))
            .unwrap()
            .unwrap();
        assert!(matches!(
            pipeline.stages_in_order().last().unwrap().kind(),
            StageKind::RateLimit(_)
        ));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.stage_added"]
        );
    }

    /// Ann adds a second Identity stage. It is refused: every pipeline runs
    /// exactly one.
    #[test]
    fn a_mandatory_stage_is_not_added() {
        let store = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = add(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            StageKind::Identity,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(stage_count(&store), 2);
    }

    /// Ann adds a stage to a pipeline running on live traffic. It is
    /// refused: she disables the pipeline first.
    #[test]
    fn an_active_pipeline_takes_no_stage() {
        let store = seeded(PipelineStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = add(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            rate_limit(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stage_count(&store), 2);
    }

    /// Ann names a pipeline the tenant does not have. It is not found.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let store = Arc::new(FakePipelineStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = add(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            rate_limit(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer cannot add a rate-limit stage; the pipeline keeps its two
    /// stages and no addition is audited.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let store = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = add(
            &store,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            &audit,
            rate_limit(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stage_count(&store), 2);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Adding a stage without change rights returns forbidden even for an
    /// unknown pipeline, withholding whether it exists.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_pipeline() {
        let result = add(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
            rate_limit(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Adding a stage with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = seeded(PipelineStatus::Draft);

        let result = add(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            rate_limit(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
