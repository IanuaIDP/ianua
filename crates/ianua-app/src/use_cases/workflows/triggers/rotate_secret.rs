//! Rotate trigger secret: a person replaces the secret a workflow's webhook
//! is called with.
//!
//! A call with the old secret starts nothing more, and the new one starts
//! only the versions the person who rotated it publishes.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{
    WorkflowStore, WorkflowTriggerSecretGenerator, WorkflowTriggerSecretStore,
};
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::{latest_version, trigger_secret_of};
use crate::use_cases::workflows::triggers::IssuedTriggerSecret;

/// The ports [`RotateSecretUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotateSecretPorts {
    /// The versions, for the workflow the secret starts.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps the webhooks' secrets.
    pub trigger_secrets: Arc<dyn WorkflowTriggerSecretStore>,
    /// Makes the new secret and its hash.
    pub secret_generator: Arc<dyn WorkflowTriggerSecretGenerator>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Replaces webhook secrets.
pub struct RotateSecretUseCase {
    ports: RotateSecretPorts,
}

impl RotateSecretUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RotateSecretPorts) -> Self {
        Self { ports }
    }
}

impl Command for RotateSecretUseCase {
    type Caller = CallerContext;
    type Input = WorkflowId;
    type Output = Result<IssuedTriggerSecret, AppError>;

    /// Replaces the secret of workflow `workflow_id`'s webhook and records
    /// `workflows.trigger_secret_rotated`. The new raw secret comes back
    /// once; only its hash is kept, and the old one stops working at once.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not edit workflows.
    /// - `AppError::NotFound` when the tenant has no such workflow, or its
    ///   webhook has no secret.
    /// - `AppError::Internal` on storage, secret or audit failure.
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
        let mut secret =
            trigger_secret_of(self.ports.trigger_secrets.as_ref(), &tenant, &workflow_id).await?;
        let (raw, hash) = self.ports.secret_generator.generate().await.or_internal()?;
        secret
            .rotate(&workflow, hash, &control)
            .map_err(AppError::from_domain)?;
        self.ports
            .trigger_secrets
            .save(&tenant, &secret)
            .await
            .or_internal()?;
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
        FakeWorkflowStore, FakeWorkflowTriggerSecretStore, HOOK_SECRET, hook_secret, hooked_by,
        trigger_secret_hash,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A webhook workflow, the store its secret is kept in, and what a
    /// rotation recorded.
    struct Rotating {
        workflow: Workflow<ResolvedTenant>,
        secrets: Arc<FakeWorkflowTriggerSecretStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Rotating {
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

        /// The caller's webhook workflow, with no secret issued.
        fn without_secret() -> Self {
            Self {
                workflow: hooked_by(&caller_person()),
                secrets: Arc::new(FakeWorkflowTriggerSecretStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The caller, holding what `authorities` say, rotates the secret.
        fn rotate(
            &self,
            authorities: FakeTenantAuthorities,
        ) -> Result<IssuedTriggerSecret, AppError> {
            let use_case = RotateSecretUseCase::new(RotateSecretPorts {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(
                    &self.workflow,
                ))),
                trigger_secrets: self.secrets.clone(),
                tenant_authorities: Arc::new(authorities),
                ..RotateSecretPorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                *self.workflow.id(),
            ))
        }

        /// The hash kept for the workflow's webhook now.
        fn kept_hash(&self) -> String {
            self.secrets
                .stored_for(self.workflow.id())
                .unwrap()
                .secret_hash()
                .as_str()
                .to_owned()
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

    /// Ann's automation server leaked the webhook's secret, so she rotates
    /// it. She is shown the new one once, only its hash is kept, and the
    /// rotation is recorded.
    #[test]
    fn a_rotated_secret_replaces_the_old_one() {
        let rotating = Rotating::issued();

        let issued = rotating.rotate(editor()).unwrap();

        assert_eq!(issued.secret.expose(), "hook-secret-1");
        assert_eq!(
            rotating.kept_hash(),
            trigger_secret_hash("hook-secret-1").as_str()
        );
        assert_eq!(rotating.records(), ["workflows.trigger_secret_rotated"]);
    }

    /// Ann rotates the secret of a webhook that has none. It is not found.
    #[test]
    fn a_webhook_without_a_secret_is_not_found() {
        let rotating = Rotating::without_secret();

        let result = rotating.rotate(editor());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(rotating.records().is_empty());
    }

    /// A workflow viewer cannot rotate a webhook secret. Its stored hash stays
    /// unchanged and no audit event is recorded.
    #[test]
    fn a_caller_who_may_not_edit_workflows_is_refused() {
        let rotating = Rotating::issued();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = rotating.rotate(sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            rotating.kept_hash(),
            trigger_secret_hash(HOOK_SECRET).as_str()
        );
        assert!(rotating.records().is_empty());
    }

    /// A signed-out session cannot rotate a webhook secret; its stored hash stays
    /// unchanged.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let rotating = Rotating::issued();

        let result = rotating.rotate(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(
            rotating.kept_hash(),
            trigger_secret_hash(HOOK_SECRET).as_str()
        );
    }
}
