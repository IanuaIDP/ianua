//! Reorder stages: rewrite the order a pipeline runs its stages in, in one
//! step.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::types::{PipelineId, StageId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::proxy::PipelineStore;
use crate::use_case::Command;
use crate::use_cases::proxy::pipeline_changes::PipelineChange;

/// Which pipeline to rewrite, and the order its stages should run in.
pub struct ReorderRequest {
    /// The pipeline to reorder.
    pub pipeline_id: PipelineId,
    /// Every stage of the pipeline, exactly once, in the order to run them.
    pub order: Vec<StageId>,
}

/// The ports [`ReorderUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReorderPorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reorders a tenant's pipeline.
pub struct ReorderUseCase {
    ports: ReorderPorts,
}

impl ReorderUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReorderPorts) -> Self {
        Self { ports }
    }
}

impl Command for ReorderUseCase {
    type Caller = CallerContext;
    type Input = ReorderRequest;
    type Output = Result<(), AppError>;

    /// Rewrites the pipeline to run its stages in `order`, and records
    /// `proxy.pipeline_reordered` with the order it now runs. Identity and
    /// Policy stay first whatever `order` says.
    ///
    /// `order` names every stage exactly once. A partial list is refused
    /// rather than applied, since the stages it leaves out would collect at
    /// the front of the pipeline, a security control moving without anyone
    /// asking.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change pipelines, or
    ///   the pipeline is active.
    /// - `AppError::NotFound` when the tenant has no such pipeline.
    /// - `AppError::Domain` when `order` is not the whole pipeline.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: ReorderRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::ChangePipeline)
            .map_err(AppError::from_domain)?;
        PipelineChange::by(caller, auditor)
            .pipeline(
                self.ports.pipeline_store.as_ref(),
                &request.pipeline_id,
                |pipeline| pipeline.reorder_stages(&request.order, &control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::proxy::pipeline::Pipeline;
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{
        FakePipelineStore, rate_limit_stage, test_pipeline_id, test_pipeline_with_rate_limit,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A draft pipeline of Identity, Policy and two rate limits, and its
    /// stage ids in the order they run.
    fn seeded() -> (Arc<FakePipelineStore>, Vec<StageId>) {
        let mut pipeline = test_pipeline_with_rate_limit(PipelineStatus::Draft);
        let admin = RoutingControl::new(anyone_holding(SystemPermission::all()));
        pipeline.add_stage(rate_limit_stage(0), &admin).unwrap();
        let order = in_order(&pipeline);
        let store = FakePipelineStore::holding(test_ctx().tenant_id(), pipeline);
        (Arc::new(store), order)
    }

    fn in_order(pipeline: &Pipeline<ResolvedTenant>) -> Vec<StageId> {
        pipeline
            .stages_in_order()
            .iter()
            .map(|stage| *stage.id())
            .collect()
    }

    fn stored_order(store: &FakePipelineStore) -> Vec<StageId> {
        in_order(
            &block_on(store.find(&test_ctx().tenant(), &test_pipeline_id()))
                .unwrap()
                .unwrap(),
        )
    }

    fn reorder(
        store: &Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        order: Vec<StageId>,
    ) -> Result<(), AppError> {
        let use_case = ReorderUseCase::new(ReorderPorts {
            pipeline_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let request = ReorderRequest {
            pipeline_id: test_pipeline_id(),
            order,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    /// Ann swaps the two rate limits. The whole order is applied in one go
    /// and recorded.
    #[test]
    fn the_whole_order_is_applied_in_one_step() {
        let (store, mut order) = seeded();
        order.swap(2, 3);
        let audit = Arc::new(FakeEventDispatcher::new());

        reorder(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            order.clone(),
        )
        .unwrap();

        assert_eq!(stored_order(&store), order);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.pipeline_reordered"]
        );
    }

    /// Ann puts a rate limit first. Identity and Policy still run ahead of
    /// it, since nothing judges a request before anyone knows who sent it.
    #[test]
    fn identity_and_policy_stay_first() {
        let (store, order) = seeded();
        let rate_limit_first = vec![order[2], order[0], order[1], order[3]];

        reorder(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            rate_limit_first,
        )
        .unwrap();

        assert_eq!(stored_order(&store)[..2], order[..2]);
    }

    /// The stages an order leaves out would collect at the front of the
    /// pipeline, moving a security control nobody touched. A partial order
    /// is refused and nothing moves.
    #[test]
    fn a_partial_order_is_refused_and_changes_nothing() {
        let (store, order) = seeded();

        let result = reorder(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            vec![order[0]],
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(stored_order(&store), order);
    }

    /// An order naming a stage the pipeline does not have is refused.
    #[test]
    fn an_unknown_stage_in_the_order_is_refused() {
        let (store, mut order) = seeded();
        order[3] = StageId::new();

        let result = reorder(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            order,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann names a pipeline the tenant does not have. It is not found.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let result = reorder(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            Vec::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer cannot swap the rate-limit stages; their stored order stays
    /// unchanged.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let (store, mut order) = seeded();
        let before = order.clone();
        order.swap(2, 3);

        let result = reorder(
            &store,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            &Arc::new(FakeEventDispatcher::new()),
            order,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stored_order(&store), before);
    }

    /// Reordering without change rights returns forbidden even for an unknown
    /// pipeline, withholding whether it exists.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_pipeline() {
        let result = reorder(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
            Vec::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot reorder the pipeline's stages.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, order) = seeded();

        let result = reorder(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            order,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
