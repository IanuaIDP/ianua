//! Issue trigger secret: a person gives a webhook workflow the secret its
//! webhook is called with.
//!
//! The secret is shown once, to the person who issued it, and only its hash
//! is kept. It starts only the versions that person publishes, so whoever
//! issues it takes on what it starts.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::triggers::secret::WorkflowTriggerSecret;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{
    WorkflowStore, WorkflowTriggerSecretGenerator, WorkflowTriggerSecretStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::latest_version;
use crate::use_cases::workflows::triggers::IssuedTriggerSecret;

/// The ports [`IssueSecretUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct IssueSecretPorts {
    /// The versions, for the workflow the secret starts.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps the webhooks' secrets.
    pub trigger_secrets: Arc<dyn WorkflowTriggerSecretStore>,
    /// Makes the secret and its hash.
    pub secret_generator: Arc<dyn WorkflowTriggerSecretGenerator>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Issues webhook secrets.
pub struct IssueSecretUseCase {
    ports: IssueSecretPorts,
}

impl IssueSecretUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: IssueSecretPorts) -> Self {
        Self { ports }
    }

    /// Refuses a workflow whose webhook already has a secret: that one is
    /// rotated or revoked instead.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when the workflow's webhook has a secret.
    /// - `AppError::Internal` when the store fails.
    async fn ensure_no_secret(
        &self,
        tenant: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<(), AppError> {
        let held = self
            .ports
            .trigger_secrets
            .find_for_workflow(tenant, workflow_id)
            .await
            .or_internal()?;
        match held {
            Some(_) => Err(AppError::Conflict(message!(
                "workflows-the-webhook-already-has-a-secret",
                "the webhook already has a secret; rotate it instead"
            ))),
            None => Ok(()),
        }
    }
}

impl Command for IssueSecretUseCase {
    type Caller = CallerContext;
    type Input = WorkflowId;
    type Output = Result<IssuedTriggerSecret, AppError>;

    /// Issues a secret for the webhook of workflow `workflow_id` and
    /// records `workflows.trigger_secret_issued`. The raw secret comes back
    /// once; only its hash is kept.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without workflow-edit rights.
    /// - `AppError::NotFound` for a missing tenant workflow; `Conflict` for an existing webhook secret.
    /// - `AppError::Domain` for a workflow without a webhook trigger; `Internal` on storage, secret or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        workflow_id: WorkflowId,
    ) -> Result<IssuedTriggerSecret, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let workflow = latest_version(self.ports.workflows.as_ref(), &tenant, &workflow_id).await?;
        self.ensure_no_secret(&tenant, &workflow_id).await?;
        let (raw, hash) = self.ports.secret_generator.generate().await.or_internal()?;
        let mut secret = WorkflowTriggerSecret::issue(&workflow, hash, &control)
            .map_err(AppError::from_domain)?;
        self.ports
            .trigger_secrets
            .save(&tenant, &secret)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), secret.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(IssuedTriggerSecret {
            trigger_id: *secret.id(),
            secret: raw,
        })
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
        FakeWorkflowStore, FakeWorkflowTriggerSecretStore, draft_by, hook_secret, hooked_by,
        published_by, tidy_step, trigger_secret_hash,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store an issue writes to, and what it recorded.
    struct Issuing {
        workflow: Workflow<ResolvedTenant>,
        secrets: Arc<FakeWorkflowTriggerSecretStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Issuing {
        /// `workflow`, with `secrets` as the secrets kept.
        fn over(
            workflow: Workflow<ResolvedTenant>,
            secrets: FakeWorkflowTriggerSecretStore,
        ) -> Self {
            Self {
                workflow,
                secrets: Arc::new(secrets),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The caller, holding what `authorities` say, issues the secret.
        fn issue(
            &self,
            authorities: FakeTenantAuthorities,
        ) -> Result<IssuedTriggerSecret, AppError> {
            let use_case = IssueSecretUseCase::new(IssueSecretPorts {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(
                    &self.workflow,
                ))),
                trigger_secrets: self.secrets.clone(),
                tenant_authorities: Arc::new(authorities),
                ..IssueSecretPorts::fakes()
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

    /// Ann issues a secret for her webhook workflow. She is shown it once,
    /// only its hash is kept, and the issue is recorded.
    #[test]
    fn an_issued_secret_is_shown_once_and_kept_hashed() {
        let issuing = Issuing::over(
            hooked_by(&caller_person()),
            FakeWorkflowTriggerSecretStore::empty(),
        );

        let issued = issuing.issue(editor()).unwrap();

        assert_eq!(issued.secret.expose(), "hook-secret-1");
        let kept = issuing.secrets.stored_for(issuing.workflow.id()).unwrap();
        assert_eq!(kept.id(), &issued.trigger_id);
        assert_eq!(kept.secret_hash(), &trigger_secret_hash("hook-secret-1"));
        assert_eq!(issuing.records(), ["workflows.trigger_secret_issued"]);
    }

    /// Ann's webhook already has a secret. Issuing another is refused, so
    /// the one her server holds keeps working until she rotates it.
    #[test]
    fn a_second_secret_is_refused() {
        let workflow = hooked_by(&caller_person());
        let held = hook_secret(&workflow, &caller_person());
        let issuing = Issuing::over(workflow, FakeWorkflowTriggerSecretStore::holding(&held));

        let result = issuing.issue(editor());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(issuing.records().is_empty());
    }

    /// Ann's workflow starts by hand, so it has no webhook. Issuing it a
    /// secret is refused and nothing is kept.
    #[test]
    fn a_workflow_without_a_webhook_gets_no_secret() {
        let by_hand = published_by(
            &caller_person(),
            draft_by(&caller_person(), vec![tidy_step("tidy")], Vec::new()),
        );
        let issuing = Issuing::over(by_hand, FakeWorkflowTriggerSecretStore::empty());

        let result = issuing.issue(editor());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(issuing.secrets.count(), 0);
    }

    /// Ann names a workflow the tenant does not have. It is not found.
    #[test]
    fn an_unknown_workflow_is_not_found() {
        let use_case = IssueSecretUseCase::new(IssueSecretPorts {
            tenant_authorities: Arc::new(editor()),
            ..IssueSecretPorts::fakes()
        });
        let sink = Arc::new(FakeEventDispatcher::new());

        let result =
            block_on(use_case.execute(&test_ctx(), &test_auditor(sink), WorkflowId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A workflow viewer cannot issue a webhook secret; no secret is saved and
    /// no audit event is recorded.
    #[test]
    fn a_caller_who_may_not_edit_workflows_is_refused() {
        let issuing = Issuing::over(
            hooked_by(&caller_person()),
            FakeWorkflowTriggerSecretStore::empty(),
        );
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = issuing.issue(sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(issuing.secrets.count(), 0);
        assert!(issuing.records().is_empty());
    }

    /// A signed-out session cannot issue a webhook secret, leaving no secret saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let issuing = Issuing::over(
            hooked_by(&caller_person()),
            FakeWorkflowTriggerSecretStore::empty(),
        );

        let result = issuing.issue(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(issuing.secrets.count(), 0);
    }
}
