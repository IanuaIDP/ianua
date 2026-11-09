//! Reconfigure stage: change the settings of a stage of one of the tenant's
//! pipelines in place.

use std::sync::Arc;

use ianua_domain::domains::proxy::stages::stage::StageKind;
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::types::{PipelineId, StageId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::data_classification::ClassificationStore;
use crate::ports::proxy::PipelineStore;
use crate::services::routing::rule_sets::ensure_reads_own_rules;
use crate::use_case::Command;
use crate::use_cases::proxy::pipeline_changes::PipelineChange;

/// Which stage of which pipeline takes which new settings.
pub struct ReconfigureRequest {
    /// The pipeline holding the stage.
    pub pipeline_id: PipelineId,
    /// The stage whose settings change.
    pub stage_id: StageId,
    /// The new settings, of the stage's own kind.
    pub kind: StageKind,
}

/// The ports [`ReconfigureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReconfigurePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// Where the tenant's classification rules are kept, which a stage
    /// reading rules must name.
    pub classification_store: Arc<dyn ClassificationStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a pipeline stage's settings in place.
pub struct ReconfigureUseCase {
    ports: ReconfigurePorts,
}

impl ReconfigureUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReconfigurePorts) -> Self {
        Self { ports }
    }
}

impl Command for ReconfigureUseCase {
    type Caller = CallerContext;
    type Input = ReconfigureRequest;
    type Output = Result<(), AppError>;

    /// Gives the stage its new settings and records
    /// `proxy.stage_reconfigured`, naming the stage and its kind but never
    /// the settings. The stage keeps its id, place and whether it is on.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change pipelines, the
    ///   pipeline is active, or the stage is Identity or Policy.
    /// - `AppError::NotFound` when the tenant has no such pipeline, or it no
    ///   such stage.
    /// - `AppError::Domain` when the settings are for another kind of stage,
    ///   read classification rules that are not the tenant's, or are set up
    ///   so the stage could not do its job.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: ReconfigureRequest,
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
        PipelineChange::by(caller, auditor)
            .pipeline(
                self.ports.pipeline_store.as_ref(),
                &request.pipeline_id,
                |pipeline| pipeline.reconfigure_stage(&request.stage_id, request.kind, &control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::proxy::stages::stage::{
        CacheConfig, CacheScope, RateLimitConfig, RateLimitKey, RedactConfig,
    };
    use ianua_domain::types::{ClassificationRuleSetId, Seconds};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::data_classification::FakeClassificationStore;
    use crate::test_support::proxy::{
        FakePipelineStore, stage_of, test_pipeline_id, test_pipeline_with_rate_limit,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A pipeline in `status` running a rate limit of 100 a minute, and that
    /// stage's id.
    fn seeded(status: PipelineStatus) -> (Arc<FakePipelineStore>, StageId) {
        let pipeline = test_pipeline_with_rate_limit(status);
        let rate_limit = stage_of(&pipeline, |kind| matches!(kind, StageKind::RateLimit(_)));
        let store = FakePipelineStore::holding(test_ctx().tenant_id(), pipeline);
        (Arc::new(store), rate_limit)
    }

    /// A rate limit of `max_requests` a minute per user.
    fn rate_limit(max_requests: u32) -> StageKind {
        StageKind::RateLimit(RateLimitConfig {
            max_requests,
            window_seconds: Seconds::new(60),
            key_by: RateLimitKey::UserId,
        })
    }

    /// Runs the use case for `stage_id` with `kind`, as `authorities` allow.
    fn reconfigure(
        store: &Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        stage_id: StageId,
        kind: StageKind,
    ) -> Result<(), AppError> {
        let use_case = ReconfigureUseCase::new(ReconfigurePorts {
            pipeline_store: store.clone(),
            classification_store: Arc::new(FakeClassificationStore::empty()),
            tenant_authorities: Arc::new(authorities),
        });
        let request = ReconfigureRequest {
            pipeline_id: test_pipeline_id(),
            stage_id,
            kind,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    /// The settings the stage `stage_id` holds in the stored pipeline.
    fn kind_of(store: &FakePipelineStore, stage_id: &StageId) -> StageKind {
        block_on(store.find(&test_ctx().tenant(), &test_pipeline_id()))
            .unwrap()
            .unwrap()
            .stages()
            .iter()
            .find(|stage| stage.id() == stage_id)
            .unwrap()
            .kind()
            .clone()
    }

    /// Ann raises the rate limit to 500 requests a minute. The stage keeps
    /// its id and carries the new limit, and the change is recorded.
    #[test]
    fn a_stages_settings_change_in_place() {
        let (store, stage) = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        reconfigure(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            stage,
            rate_limit(500),
        )
        .unwrap();

        assert_eq!(kind_of(&store, &stage), rate_limit(500));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.stage_reconfigured"]
        );
    }

    /// Settings naming unavailable classification rules receive the specific
    /// rules refusal, leaving the rate limit unchanged and the audit empty.
    #[test]
    fn settings_reading_rules_that_are_not_the_tenants_are_refused() {
        let (store, stage) = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());
        let elsewhere = StageKind::Redact(RedactConfig {
            rule_set_id: ClassificationRuleSetId::new(),
            min_class: DataClassLevel::Confidential,
        });

        let result = reconfigure(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            stage,
            elsewhere,
        );

        let Err(AppError::Domain(refused)) = result else {
            panic!("settings reading no rules of the tenant's were taken: {result:?}");
        };
        assert_eq!(
            refused.refusal().and_then(|refusal| refusal.key()),
            Some("proxy-stage-reads-no-rules")
        );
        assert_eq!(kind_of(&store, &stage), rate_limit(100));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Reconfiguring a rate limit as a cache is refused, preserving its limit
    /// of 100 requests and adding no audit record.
    #[test]
    fn a_stage_does_not_become_another_kind() {
        let (store, stage) = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = reconfigure(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            stage,
            StageKind::Cache(CacheConfig {
                ttl_seconds: Seconds::new(60),
                vary_by_user: CacheScope::PerUser,
            }),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(kind_of(&store, &stage), rate_limit(100));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann sets the rate limit to zero requests, which would block every
    /// caller. It is refused and the old limit stays.
    #[test]
    fn settings_the_stage_cannot_work_with_are_refused() {
        let (store, stage) = seeded(PipelineStatus::Draft);

        let result = reconfigure(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            stage,
            rate_limit(0),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(kind_of(&store, &stage), rate_limit(100));
    }

    /// The Identity stage has no settings. Reconfiguring it is refused.
    #[test]
    fn the_identity_stage_is_not_reconfigured() {
        let (store, _) = seeded(PipelineStatus::Draft);
        let identity = stage_of(
            &block_on(store.find(&test_ctx().tenant(), &test_pipeline_id()))
                .unwrap()
                .unwrap(),
            |kind| matches!(kind, StageKind::Identity),
        );

        let result = reconfigure(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            identity,
            StageKind::Identity,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A live pipeline is not edited: changing a stage of one is refused.
    #[test]
    fn a_stage_of_a_live_pipeline_is_not_reconfigured() {
        let (store, stage) = seeded(PipelineStatus::Active);

        let result = reconfigure(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            stage,
            rate_limit(500),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(kind_of(&store, &stage), rate_limit(100));
    }

    /// Ann names a stage the pipeline does not have. It is not found.
    #[test]
    fn an_unknown_stage_is_not_found() {
        let (store, _) = seeded(PipelineStatus::Draft);

        let result = reconfigure(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            StageId::new(),
            rate_limit(500),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann names a pipeline the tenant does not have. It is not found.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let result = reconfigure(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            StageId::new(),
            rate_limit(500),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer cannot raise the rate limit; its 100-request setting remains
    /// and no reconfiguration is audited.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let (store, stage) = seeded(PipelineStatus::Draft);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = reconfigure(
            &store,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            &audit,
            stage,
            rate_limit(1_000_000),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(kind_of(&store, &stage), rate_limit(100));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Reconfiguring a stage with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, stage) = seeded(PipelineStatus::Draft);

        let result = reconfigure(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            stage,
            rate_limit(500),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
