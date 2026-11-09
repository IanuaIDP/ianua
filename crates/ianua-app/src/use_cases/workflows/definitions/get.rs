//! Get workflow: one version of a workflow, for someone who may view
//! workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::WorkflowStore;
use crate::use_case::Query;
use crate::use_cases::workflows::lookup::designed_version;

/// Which version of a workflow to read.
pub enum WhichVersion {
    /// The highest-numbered one.
    Latest,
    /// An explicit numbered revision, even when it is not the latest.
    Number(u32),
}

/// The workflow and version to read.
pub struct GetWorkflowRequest {
    /// The automation definition whose stored revision is requested.
    pub workflow_id: WorkflowId,
    /// The latest revision or a specific numbered revision to retrieve.
    pub version: WhichVersion,
}

/// The ports [`GetWorkflowUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetWorkflowPorts {
    /// Keeps the versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one version of a workflow.
pub struct GetWorkflowUseCase {
    ports: GetWorkflowPorts,
}

impl GetWorkflowUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetWorkflowPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetWorkflowUseCase {
    type Caller = CallerContext;
    type Input = GetWorkflowRequest;
    type Output = Result<Workflow<ResolvedTenant>, AppError>;

    /// The version `request` names, for the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::NotFound` when the tenant has no such workflow or
    ///   version, or it is an agent flow, which is read as a flow.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: GetWorkflowRequest,
    ) -> Result<Workflow<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let version = match request.version {
            WhichVersion::Latest => None,
            WhichVersion::Number(number) => Some(number),
        };
        designed_version(
            self.ports.workflows.as_ref(),
            &ctx.tenant(),
            &request.workflow_id,
            version,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowStore, draft_by, flow_by, managing, published_by, tidy_step,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Version 1 in service and version 2 drafted, of one workflow.
    fn two_versions() -> Vec<Workflow<ResolvedTenant>> {
        let first = published_by(
            &caller_person(),
            draft_by(&caller_person(), vec![tidy_step("tidy")], Vec::new()),
        );
        let second = first.next_draft(&managing(&caller_person())).unwrap();
        vec![first, second]
    }

    fn read(
        versions: &[Workflow<ResolvedTenant>],
        authorities: FakeTenantAuthorities,
        version: WhichVersion,
    ) -> Result<Workflow<ResolvedTenant>, AppError> {
        let use_case = GetWorkflowUseCase::new(GetWorkflowPorts {
            workflows: Arc::new(FakeWorkflowStore::holding(versions)),
            tenant_authorities: Arc::new(authorities),
        });
        let request = GetWorkflowRequest {
            workflow_id: *versions[0].id(),
            version,
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Ann, who may view workflows, reads the latest version and then
    /// version 1. She gets version 2 and version 1.
    #[test]
    fn a_viewer_reads_the_latest_or_a_numbered_version() {
        let versions = two_versions();

        let latest = read(&versions, viewer(), WhichVersion::Latest).unwrap();
        let first = read(&versions, viewer(), WhichVersion::Number(1)).unwrap();

        assert_eq!(latest.version(), 2);
        assert_eq!(first.version(), 1);
    }

    /// Ann made an agent flow and asks for it as a designed workflow. It is
    /// not found here: a flow is read as a flow.
    #[test]
    fn an_agent_flow_is_not_read_as_a_workflow() {
        let flow = flow_by(&caller_person());

        let result = read(&[flow], viewer(), WhichVersion::Latest);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann asks for version 9 of a workflow with two. It is not found.
    #[test]
    fn a_version_that_does_not_exist_is_not_found() {
        let result = read(&two_versions(), viewer(), WhichVersion::Number(9));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without workflow rights cannot read the latest workflow version.
    #[test]
    fn a_caller_who_may_not_view_workflows_is_refused() {
        let result = read(
            &two_versions(),
            FakeTenantAuthorities::holding(&[]),
            WhichVersion::Latest,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read a workflow version.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(
            &two_versions(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            WhichVersion::Latest,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
