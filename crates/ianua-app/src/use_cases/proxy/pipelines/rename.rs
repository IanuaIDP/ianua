//! Rename pipeline: give one of the tenant's pipelines another name.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, PipelineId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::proxy::PipelineStore;
use crate::use_case::Command;
use crate::use_cases::proxy::lookup::existing_pipeline;
use crate::use_cases::proxy::pipeline_changes::pipeline_error;

/// The ports [`RenameUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenamePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which pipeline to rename, and its new name.
pub struct RenameRequest {
    /// The pipeline to rename.
    pub pipeline_id: PipelineId,
    /// The name it is to carry.
    pub name: Label,
}

/// Renames one of a tenant's pipelines.
pub struct RenameUseCase {
    ports: RenamePorts,
}

impl RenameUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenamePorts) -> Self {
        Self { ports }
    }
}

impl Command for RenameUseCase {
    type Caller = CallerContext;
    type Input = RenameRequest;
    type Output = Result<(), AppError>;

    /// Renames the pipeline and records `proxy.pipeline_renamed` with both
    /// names. Routes name it by id, so they keep running it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change pipelines.
    /// - `AppError::NotFound` when the tenant has no such pipeline.
    /// - `AppError::Conflict` when the tenant already has a pipeline by the
    ///   new name.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: RenameRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::ChangePipeline)
            .map_err(AppError::from_domain)?;
        let store = self.ports.pipeline_store.as_ref();
        let tenant = caller.tenant();
        let mut pipeline = existing_pipeline(store, &tenant, &request.pipeline_id).await?;
        pipeline
            .rename(request.name, &control)
            .map_err(|error| pipeline_error(&error))?;
        store
            .save(&tenant, &pipeline)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&authority.actor(), pipeline.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::domains::proxy::pipeline::Pipeline;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{FakePipelineStore, test_pipeline, test_pipeline_id};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn label(name: &str) -> Label {
        Label::new("pipeline_name", name).unwrap()
    }

    fn seeded() -> Arc<FakePipelineStore> {
        Arc::new(FakePipelineStore::holding(
            test_ctx().tenant_id(),
            test_pipeline(),
        ))
    }

    fn rename(
        store: &Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
        name: &str,
    ) -> Result<(), AppError> {
        rename_recorded(
            store,
            authorities,
            name,
            &Arc::new(FakeEventDispatcher::new()),
        )
    }

    fn rename_recorded(
        store: &Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
        name: &str,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<(), AppError> {
        let use_case = RenameUseCase::new(RenamePorts {
            pipeline_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let request = RenameRequest {
            pipeline_id: test_pipeline_id(),
            name: label(name),
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn name_of(store: &FakePipelineStore) -> String {
        block_on(store.find(&test_ctx().tenant(), &test_pipeline_id()))
            .unwrap()
            .unwrap()
            .name()
            .as_str()
            .to_owned()
    }

    /// Ann renames the pipeline Default to Strict. It is stored under the
    /// new name.
    #[test]
    fn a_pipeline_is_renamed() {
        let store = seeded();

        rename(
            &store,
            FakeTenantAuthorities::holding_everything(),
            "Strict",
        )
        .unwrap();

        assert_eq!(name_of(&store), "Strict");
    }

    /// Ann renames the pipeline Default to Strict. The audit trail keeps
    /// both names.
    #[test]
    fn renaming_a_pipeline_is_recorded_with_both_names() {
        let audit = Arc::new(FakeEventDispatcher::new());

        rename_recorded(
            &seeded(),
            FakeTenantAuthorities::holding_everything(),
            "Strict",
            &audit,
        )
        .unwrap();

        let payload = audit.payload_of("proxy.pipeline_renamed");
        let Some(FieldValue::Change(change)) = payload.value("name") else {
            panic!("name is not a change");
        };
        assert_eq!(change.to(), Some("Strict"));
    }

    /// Acme already has a pipeline named Strict. Ann renames Default to
    /// Strict too. It is refused as a conflict and Default keeps its name.
    #[test]
    fn a_name_the_tenant_already_uses_is_refused() {
        let store = seeded();
        let keeper = anyone_holding(&[SystemPermission::Pipeline(PipelineAction::Manage)]);
        let strict = Pipeline::<ResolvedTenant>::with_defaults(
            label("Strict"),
            &RoutingControl::new(keeper),
        )
        .unwrap();
        block_on(store.save(&test_ctx().tenant(), &strict)).unwrap();

        let result = rename(
            &store,
            FakeTenantAuthorities::holding_everything(),
            "Strict",
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(name_of(&store), "Default");
    }

    /// Ann names a pipeline the tenant does not have. It is not found.
    #[test]
    fn an_unknown_pipeline_is_not_found() {
        let result = rename(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            "Strict",
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer's rename is refused, leaving the pipeline named Default.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let store = seeded();

        let result = rename(
            &store,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            "Strict",
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(name_of(&store), "Default");
    }

    /// Renaming an unknown pipeline without change rights returns forbidden
    /// rather than revealing its absence.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_pipeline() {
        let result = rename(
            &Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::holding(&[]),
            "Strict",
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Renaming with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = rename(
            &seeded(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            "Strict",
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
