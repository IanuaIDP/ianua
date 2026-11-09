//! Configure pipeline: create one of the tenant's proxy pipelines.

use std::sync::Arc;

use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, PipelineId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::proxy::PipelineStore;
use crate::use_case::Command;
use crate::use_cases::proxy::pipeline_changes::pipeline_error;

/// The ports [`ConfigureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfigurePorts {
    /// Where pipelines are kept.
    pub pipeline_store: Arc<dyn PipelineStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Creates one of a tenant's pipelines.
pub struct ConfigureUseCase {
    ports: ConfigurePorts,
}

impl ConfigureUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConfigurePorts) -> Self {
        Self { ports }
    }
}

impl Command for ConfigureUseCase {
    type Caller = CallerContext;
    type Input = Label;
    type Output = Result<PipelineId, AppError>;

    /// Creates a pipeline named `name`, carrying the mandatory stages, and
    /// records `proxy.pipeline_created`.
    ///
    /// A tenant may hold any number of them; the name tells them apart. The
    /// new one starts `Draft` and carries no traffic until it is activated
    /// and a route runs it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage pipelines.
    /// - `AppError::Conflict` when the tenant already has a pipeline by this
    ///   name.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        name: Label,
    ) -> Result<PipelineId, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let mut pipeline =
            Pipeline::<ResolvedTenant>::with_defaults(name, &RoutingControl::new(&authority))
                .map_err(|error| pipeline_error(&error))?;
        let tenant = caller.tenant();

        self.ports
            .pipeline_store
            .save(&tenant, &pipeline)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), pipeline.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(*pipeline.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::FakePipelineStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn use_case(
        store: Arc<FakePipelineStore>,
        authorities: FakeTenantAuthorities,
    ) -> ConfigureUseCase {
        ConfigureUseCase::new(ConfigurePorts {
            pipeline_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn create(
        use_case: &ConfigureUseCase,
        audit: &Arc<FakeEventDispatcher>,
        name: &str,
    ) -> Result<PipelineId, AppError> {
        block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(audit.clone()),
            Label::new("pipeline_name", name).unwrap(),
        ))
    }

    fn stored(store: &FakePipelineStore, id: &PipelineId) -> Option<Pipeline<ResolvedTenant>> {
        block_on(store.find(&test_ctx().tenant(), id)).unwrap()
    }

    /// Ann creates a pipeline named Strict. It is stored under that name and
    /// the creation recorded.
    #[test]
    fn a_pipeline_admin_creates_a_named_pipeline() {
        let store = Arc::new(FakePipelineStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        let id = create(&use_case, &audit, "Strict").unwrap();

        assert_eq!(stored(&store, &id).unwrap().name().as_str(), "Strict");
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.pipeline_created"]
        );
    }

    /// A second pipeline is a new one, not a replacement. That is what lets
    /// Ann move routes from one to the other.
    #[test]
    fn a_second_pipeline_gets_its_own_id() {
        let store = Arc::new(FakePipelineStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        let first = create(&use_case, &audit, "Default").unwrap();
        let second = create(&use_case, &audit, "Strict").unwrap();

        assert_ne!(first, second);
        assert!(stored(&store, &first).is_some());
    }

    /// Ann names a second pipeline Default, as the first. It is refused as
    /// a conflict.
    #[test]
    fn a_taken_name_is_refused() {
        let store = Arc::new(FakePipelineStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());
        create(&use_case, &audit, "Default").unwrap();

        let result = create(&use_case, &audit, "Default");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Pipeline-update rights do not permit creating another pipeline; the
    /// refusal adds no creation audit record.
    #[test]
    fn a_caller_without_the_manage_right_is_refused() {
        let store = Arc::new(FakePipelineStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::Update)]),
        );

        let result = create(&use_case, &audit, "Open");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Creating a pipeline with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case(
            Arc::new(FakePipelineStore::empty()),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = create(&use_case, &Arc::new(FakeEventDispatcher::new()), "Strict");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
