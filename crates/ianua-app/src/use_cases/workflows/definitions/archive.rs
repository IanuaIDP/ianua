//! Archive workflow: a person takes one version out of service for good.
//!
//! Archiving is how a workflow is removed: the version never runs again,
//! its schedules stop and its registrations at services are removed. It
//! needs the right to delete workflows, not merely to edit them.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::triggers::subscription::ServiceSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::WorkflowStore;
use crate::services::kept_together::kept_together;
use crate::services::registrations::{RegistrationPorts, retired, unregister};
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::stored_version;

/// Which version to take out of service.
pub struct ArchiveWorkflowRequest {
    /// The automation definition whose published revision is being retired.
    pub workflow_id: WorkflowId,
    /// The numbered revision to remove from service.
    pub version: u32,
}

/// The ports [`ArchiveWorkflowUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ArchiveWorkflowPorts {
    /// Keeps the versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Removes the version's registrations at services.
    pub registrations: RegistrationPorts,
    /// Keeps the version, its registrations and their records together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Takes workflow versions out of service.
pub struct ArchiveWorkflowUseCase {
    ports: ArchiveWorkflowPorts,
}

impl ArchiveWorkflowUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ArchiveWorkflowPorts) -> Self {
        Self { ports }
    }

    /// Saves the archived version and its removed registrations, and
    /// records what each raised.
    async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        workflow: &mut Workflow<ResolvedTenant>,
        removed: &mut [ServiceSubscription<ResolvedTenant>],
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        self.ports
            .workflows
            .save(&tenant, workflow)
            .await
            .map_err(AppError::from_domain)?;
        let mut events = workflow.take_events(&tenant);
        for subscription in removed.iter_mut() {
            self.ports
                .registrations
                .subscriptions
                .save(&tenant, subscription)
                .await
                .or_internal()?;
            events.extend(subscription.take_events(&tenant));
        }
        auditor
            .dispatch_by(&ctx.actor(), events)
            .await
            .or_internal()
    }
}

impl Command for ArchiveWorkflowUseCase {
    type Caller = CallerContext;
    type Input = ArchiveWorkflowRequest;
    type Output = Result<Workflow<ResolvedTenant>, AppError>;

    /// Archives the version `request` names, as the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such version.
    /// - `AppError::Forbidden` when the caller may not delete workflows.
    /// - `AppError::Domain` when the version is already archived.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ArchiveWorkflowRequest,
    ) -> Result<Workflow<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut workflow = stored_version(
            self.ports.workflows.as_ref(),
            &ctx.tenant(),
            &request.workflow_id,
            request.version,
        )
        .await?;
        workflow
            .archive(&WorkflowControl::new(&authority))
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut removed = retired(&self.ports.registrations, &tenant, &workflow).await?;
        kept_together(
            self.ports.unit_of_work.as_ref(),
            self.keep(ctx, auditor, &mut workflow, &mut removed),
        )
        .await?;
        unregister(&self.ports.registrations, auditor, &tenant, &removed).await;
        Ok(workflow)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::design::workflow::WorkflowStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{FakeWorkflowStore, draft_by, published_by, tidy_step};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The version an archive reads and writes, and what it recorded.
    struct Archiving {
        workflows: Arc<FakeWorkflowStore>,
        sink: Arc<FakeEventDispatcher>,
        id: WorkflowId,
    }

    impl Archiving {
        fn of_published() -> Self {
            let workflow = published_by(
                &caller_person(),
                draft_by(&caller_person(), vec![tidy_step("tidy")], Vec::new()),
            );
            Self {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(&workflow))),
                sink: Arc::new(FakeEventDispatcher::new()),
                id: *workflow.id(),
            }
        }

        fn archive(
            &self,
            authorities: FakeTenantAuthorities,
            version: u32,
        ) -> Result<Workflow<ResolvedTenant>, AppError> {
            let use_case = ArchiveWorkflowUseCase::new(ArchiveWorkflowPorts {
                workflows: self.workflows.clone(),
                tenant_authorities: Arc::new(authorities),
                ..ArchiveWorkflowPorts::fakes()
            });
            let request = ArchiveWorkflowRequest {
                workflow_id: self.id,
                version,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        fn status(&self) -> WorkflowStatus {
            self.workflows.stored(&self.id, 1).unwrap().status()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn holding(action: WorkflowAction) -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(action)])
    }

    /// Ann, who may delete workflows, archives the version in service. It
    /// is archived and the archive is recorded.
    #[test]
    fn a_version_is_archived_and_recorded() {
        let archiving = Archiving::of_published();

        archiving
            .archive(holding(WorkflowAction::Delete), 1)
            .unwrap();

        assert_eq!(archiving.status(), WorkflowStatus::Archived);
        assert_eq!(archiving.records(), ["workflows.version_archived"]);
    }

    /// Workflow update rights do not permit archiving a published version. It
    /// remains published and no audit event is recorded.
    #[test]
    fn archiving_needs_the_right_to_delete() {
        let archiving = Archiving::of_published();

        let result = archiving.archive(holding(WorkflowAction::Update), 1);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(archiving.status(), WorkflowStatus::Published);
        assert!(archiving.records().is_empty());
    }

    /// Ann asks to archive version 7 of a workflow that has one version. It
    /// is not found.
    #[test]
    fn a_version_that_does_not_exist_is_not_found() {
        let archiving = Archiving::of_published();

        let result = archiving.archive(holding(WorkflowAction::Delete), 7);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot archive a version, which remains published.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let archiving = Archiving::of_published();

        let result = archiving.archive(FakeTenantAuthorities::refusing(Refusal::SignedOut), 1);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(archiving.status(), WorkflowStatus::Published);
    }
}
