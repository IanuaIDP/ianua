//! List events: every event the installed integrations' services send that
//! a workflow may start on, with its guide, for someone who may view
//! workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::integration::events::{ServiceEventGuide, ServiceEventSpec};
use ianua_domain::shared::errors::DomainError;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::IntegrationCatalog;
use crate::use_case::Query;

/// One event a workflow may start on: as its integration declares it, and
/// how it explains it.
#[derive(Debug, Clone)]
pub struct OfferedEvent {
    /// The event and the filters it takes.
    pub spec: ServiceEventSpec,
    /// When it happens, what its filters mean and what it gives the
    /// workflow.
    pub guide: ServiceEventGuide,
}

/// The ports [`ListEventsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListEventsPorts {
    /// The integrations installed and what they declare.
    pub catalog: Arc<dyn IntegrationCatalog>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the events a workflow may start on.
pub struct ListEventsUseCase {
    ports: ListEventsPorts,
}

impl ListEventsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListEventsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListEventsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<OfferedEvent>, AppError>;

    /// Every event every installed integration offers, integration by
    /// integration, each with its guide.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when the catalog cannot be read, or an event
    ///   has no guide.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<Vec<OfferedEvent>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let catalog = self.ports.catalog.as_ref();
        let mut offered = Vec::new();
        for profile in catalog.installed().await.or_internal()? {
            let guides = catalog.event_guides(profile.key()).await.or_internal()?;
            for spec in catalog.events(profile.key()).await.or_internal()? {
                let guide = guides
                    .iter()
                    .find(|guide| guide.event() == spec.event())
                    .cloned()
                    .ok_or_else(|| unexplained(&spec))?;
                offered.push(OfferedEvent { spec, guide });
            }
        }
        Ok(offered)
    }
}

/// The failure for an event its integration does not explain, which the
/// platform refuses to start with.
fn unexplained(spec: &ServiceEventSpec) -> AppError {
    AppError::from_domain(DomainError::infra_msg(format!(
        "{}.{} has no guide",
        spec.integration(),
        spec.event()
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::data::FieldName;
    use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
    use ianua_domain::domains::workflows::integration::{InputNeed, InputSpec, IntegrationKey};
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{FakeIntegrationCatalog, SHEETS, append_row};
    use crate::test_support::{block_on, test_ctx};

    fn row_added() -> ServiceEventSpec {
        ServiceEventSpec::new(
            IntegrationKey::new(SHEETS).unwrap(),
            ServiceEventKey::new("row-added").unwrap(),
            vec![InputSpec::new(
                FieldName::new("sheet").unwrap(),
                InputNeed::Required,
            )],
        )
        .unwrap()
    }

    fn list(authorities: FakeTenantAuthorities) -> Result<Vec<OfferedEvent>, AppError> {
        let use_case = ListEventsUseCase::new(ListEventsPorts {
            catalog: Arc::new(
                FakeIntegrationCatalog::offering(vec![append_row(ActionClass::Write)])
                    .with_events(vec![row_added()]),
            ),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann builds a workflow and is offered "a row is added" from the
    /// sheets integration, explained with its one filter.
    #[test]
    fn each_offered_event_is_listed_with_its_guide() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let listed = list(viewer).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].spec.event().as_str(), "row-added");
        assert_eq!(listed[0].guide.filters().len(), 1);
    }

    /// Listing integration events requires workflow view rights.
    #[test]
    fn a_caller_who_may_not_view_workflows_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
