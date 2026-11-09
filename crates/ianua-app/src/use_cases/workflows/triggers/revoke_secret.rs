//! Revoke trigger secret: a person withdraws the secret a workflow's webhook
//! is called with, so the webhook starts nothing until a new one is issued.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{WorkflowStore, WorkflowTriggerSecretStore};
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::{latest_version, trigger_secret_of};

/// The ports [`RevokeSecretUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeSecretPorts {
    /// The versions, for the workflow the secret starts.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps the webhooks' secrets.
    pub trigger_secrets: Arc<dyn WorkflowTriggerSecretStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Withdraws webhook secrets.
pub struct RevokeSecretUseCase {
    ports: RevokeSecretPorts,
}

impl RevokeSecretUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeSecretPorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeSecretUseCase {
    type Caller = CallerContext;
    type Input = WorkflowId;
    type Output = Result<(), AppError>;

    /// Deletes the secret of workflow `workflow_id`'s webhook and records
    /// `workflows.trigger_secret_revoked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not edit workflows.
    /// - `AppError::NotFound` when the tenant has no such workflow, or its
    ///   webhook has no secret.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        workflow_id: WorkflowId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let workflow = latest_version(self.ports.workflows.as_ref(), &tenant, &workflow_id).await?;
        let mut secret =
            trigger_secret_of(self.ports.trigger_secrets.as_ref(), &tenant, &workflow_id).await?;
        secret
            .revoke(&workflow, &control)
            .map_err(AppError::from_domain)?;
        self.ports
            .trigger_secrets
            .delete(&tenant, secret.id())
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), secret.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::workflows::{
        FakeWorkflowStore, FakeWorkflowTriggerSecretStore, hook_secret, hooked_by,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A webhook workflow, the store its secret is kept in, and what a
    /// revocation recorded.
    struct Revoking {
        workflow: Workflow<ResolvedTenant>,
        secrets: Arc<FakeWorkflowTriggerSecretStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Revoking {
        /// The caller's webhook workflow, with its secret issued.
        fn issued() -> Self {
            let workflow = hooked_by(&caller_person());
            let held = hook_secret(&workflow, &caller_person());
            Self {
                workflow,
                secrets: Arc::new(FakeWorkflowTriggerSecretStore::holding(&held)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The caller, holding what `authorities` say, revokes the secret.
        fn revoke(&self, authorities: FakeTenantAuthorities) -> Result<(), AppError> {
            let use_case = RevokeSecretUseCase::new(RevokeSecretPorts {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(
                    &self.workflow,
                ))),
                trigger_secrets: self.secrets.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                *self.workflow.id(),
            ))
        }

        /// The names of the events recorded.
        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Someone who may edit workflows.
    fn editor() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Update)])
    }

    /// Ann retires the integration that called her webhook and revokes its
    /// secret. It is deleted, and the revocation is recorded.
    #[test]
    fn a_revoked_secret_is_deleted_and_recorded() {
        let revoking = Revoking::issued();

        revoking.revoke(editor()).unwrap();

        assert_eq!(revoking.secrets.count(), 0);
        assert_eq!(revoking.records(), ["workflows.trigger_secret_revoked"]);
    }

    /// Ann revokes the secret of a webhook that has none. It is not found.
    #[test]
    fn a_webhook_without_a_secret_is_not_found() {
        let revoking = Revoking {
            secrets: Arc::new(FakeWorkflowTriggerSecretStore::empty()),
            ..Revoking::issued()
        };

        let result = revoking.revoke(editor());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(revoking.records().is_empty());
    }

    /// A workflow viewer cannot revoke a webhook secret. The secret remains
    /// saved and no audit event is recorded.
    #[test]
    fn a_caller_who_may_not_edit_workflows_is_refused() {
        let revoking = Revoking::issued();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = revoking.revoke(sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(revoking.secrets.count(), 1);
        assert!(revoking.records().is_empty());
    }

    /// A signed-out session cannot revoke a webhook secret, which remains saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let revoking = Revoking::issued();

        let result = revoking.revoke(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(revoking.secrets.count(), 1);
    }
}
