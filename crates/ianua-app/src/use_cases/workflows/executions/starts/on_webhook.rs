//! Start on webhook: someone calls a workflow's webhook with its secret, and
//! the version in service starts for the person who published it.
//!
//! Nobody signs in for this; the secret is the only proof. A call without
//! the right secret, for a secret nobody issued, or for a version its
//! secret does not start, is refused one way, so a caller without the
//! secret learns nothing about the workflow behind the address.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::execution::Cause;
use ianua_domain::domains::workflows::triggers::secret::WebhookCall;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::WorkflowTriggerId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{WorkflowTriggerSecretGenerator, WorkflowTriggerSecretStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::executions::starts::triggered::{
    Admission, Firing, started_for_publisher,
};
use crate::use_cases::workflows::executions::{TriggerStartPorts, TriggeredStart};

/// One call of a workflow's webhook.
pub struct StartOnWebhookRequest {
    /// The secret's id, which the webhook's address names.
    pub trigger_id: WorkflowTriggerId,
    /// The secret the call presented.
    pub presented: Secret,
    /// The data the call carried.
    pub input: FlowData,
    /// The most sensitive data in it, as the endpoint that received it
    /// classed it.
    pub exposure: DataClassLevel,
}

/// The ports [`StartOnWebhookUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartOnWebhookPorts {
    /// Keeps the webhooks' secrets.
    pub trigger_secrets: Arc<dyn WorkflowTriggerSecretStore>,
    /// Hashes the secret a call presented, to check it.
    pub secret_hasher: Arc<dyn WorkflowTriggerSecretGenerator>,
    /// What a start for the publisher needs.
    pub starts: TriggerStartPorts,
}

/// Starts versions when their webhook is called with its secret.
pub struct StartOnWebhookUseCase {
    ports: StartOnWebhookPorts,
}

impl StartOnWebhookUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartOnWebhookPorts) -> Self {
        Self { ports }
    }

    /// The version in service the call starts, and the call its secret
    /// admitted for it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when no secret has `trigger_id`, no
    ///   version of its workflow is in service, or the domain does not
    ///   admit the call.
    /// - `AppError::Internal` when a store fails.
    async fn admitted(
        &self,
        tenant: &ScopedTenant,
        trigger_id: &WorkflowTriggerId,
        presented: &Secret,
    ) -> Result<(Workflow<ResolvedTenant>, WebhookCall), AppError> {
        let found = self
            .ports
            .trigger_secrets
            .find_by_id(tenant, trigger_id)
            .await
            .or_internal()?;
        let Some(secret) = found else {
            return Err(AppError::Unauthenticated);
        };
        let in_service = self
            .ports
            .starts
            .workflows
            .find_published(tenant, secret.workflow_id())
            .await
            .or_internal()?;
        let Some(workflow) = in_service else {
            return Err(AppError::Unauthenticated);
        };
        let hash = self.ports.secret_hasher.hash_presented(presented);
        let call = secret.admit(&hash, &workflow).map_err(refused_call)?;
        Ok((workflow, call))
    }
}

impl Command for StartOnWebhookUseCase {
    type Caller = ScopedTenant;
    type Input = StartOnWebhookRequest;
    type Output = Result<TriggeredStart, AppError>;

    /// Starts the version in service of the workflow whose webhook was
    /// called, for its publisher, once the secret admits the call; or
    /// records why the publisher may not have it start.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the call is not admitted: an
    ///   unknown secret, a wrong one, a workflow with no version in
    ///   service, or a version someone other than the secret's issuer
    ///   published.
    /// - `AppError::Internal` when a store fails, the publisher's records
    ///   name a role that is not there, or the start or its record cannot
    ///   be kept.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: StartOnWebhookRequest,
    ) -> Result<TriggeredStart, AppError> {
        let (workflow, call) = self
            .admitted(tenant, &request.trigger_id, &request.presented)
            .await?;
        let firing = Firing {
            cause: Cause::Webhook,
            admission: Admission::Webhook(call),
            input: request.input,
            exposure: request.exposure,
        };
        started_for_publisher(&self.ports.starts, tenant, auditor, &workflow, firing).await
    }
}

/// The one answer a call the domain does not admit gets, whatever the
/// reason, so a guess learns nothing about the workflow.
fn refused_call(_why: DomainError) -> AppError {
    AppError::Unauthenticated
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::execution::StartRefusal;
    use ianua_domain::domains::workflows::triggers::secret::WorkflowTriggerSecret;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, FakeWorkflowTriggerSecretStore, HOOK_SECRET,
        accounts_now_of, hook_secret, hooked_by, person, trigger_data,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const RUNS: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Run)];

    /// A webhook workflow, its secret, and what a call wrote and recorded.
    struct Hook {
        workflow: Workflow<ResolvedTenant>,
        secret: WorkflowTriggerSecret<ResolvedTenant>,
        executions: Arc<FakeWorkflowExecutionStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Hook {
        /// The webhook workflow `publisher` published, with the secret
        /// `issuer` issued for it.
        fn published_by(publisher: &Human, issuer: &Human) -> Self {
            let workflow = hooked_by(publisher);
            let secret = hook_secret(&workflow, issuer);
            Self {
                workflow,
                secret,
                executions: Arc::new(FakeWorkflowExecutionStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// A call of the webhook `trigger_id` with `presented`, the tenant's
        /// records being `accounts_now`.
        fn call(
            &self,
            trigger_id: WorkflowTriggerId,
            presented: &str,
            accounts_now: AccountsNowOf<'_>,
        ) -> Result<TriggeredStart, AppError> {
            let use_case = StartOnWebhookUseCase::new(StartOnWebhookPorts {
                trigger_secrets: Arc::new(FakeWorkflowTriggerSecretStore::holding(&self.secret)),
                starts: TriggerStartPorts {
                    workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(
                        &self.workflow,
                    ))),
                    executions: self.executions.clone(),
                    accounts_now: Arc::new(accounts_now_of(accounts_now)),
                    ..TriggerStartPorts::fakes()
                },
                ..StartOnWebhookPorts::fakes()
            });
            let request = StartOnWebhookRequest {
                trigger_id,
                presented: Secret::new(presented),
                input: trigger_data(),
                exposure: DataClassLevel::Internal,
            };
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                request,
            ))
        }

        /// A call of this webhook with `presented`.
        fn call_with(
            &self,
            presented: &str,
            accounts_now: AccountsNowOf<'_>,
        ) -> Result<TriggeredStart, AppError> {
            self.call(*self.secret.id(), presented, accounts_now)
        }

        /// The names of the events recorded.
        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// The people the tenant's records hold, with what each may do.
    type AccountsNowOf<'a> = &'a [(&'a Human, &'a [SystemPermission])];

    /// Ann published a webhook workflow and issued its secret. Her
    /// automation server calls it with the secret. It runs acting for Ann,
    /// and the start is recorded.
    #[test]
    fn a_call_with_the_secret_starts_the_version_for_its_publisher() {
        let ann = person("ann@corp.test");
        let hook = Hook::published_by(&ann, &ann);

        let outcome = hook.call_with(HOOK_SECRET, &[(&ann, &RUNS)]).unwrap();

        let TriggeredStart::Started(id) = outcome else {
            panic!("the call did not start the workflow");
        };
        let kept = hook.executions.stored(&id).unwrap();
        assert!(kept.acting_for().is_same_account_as(&ann));
        assert_eq!(kept.cause(), Cause::Webhook);
        assert_eq!(hook.records()[0], "workflows.execution_started");
    }

    /// A wrong webhook secret fails authentication without saving an execution
    /// or recording an audit event.
    #[test]
    fn a_call_with_a_wrong_secret_is_refused() {
        let ann = person("ann@corp.test");
        let hook = Hook::published_by(&ann, &ann);

        let result = hook.call_with("guessed", &[(&ann, &RUNS)]);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(hook.executions.all().is_empty());
        assert!(hook.records().is_empty());
    }

    /// An unknown webhook ID fails authentication without saving an execution.
    #[test]
    fn a_call_of_an_unknown_webhook_is_refused_the_same_way() {
        let ann = person("ann@corp.test");
        let hook = Hook::published_by(&ann, &ann);

        let result = hook.call(WorkflowTriggerId::new(), HOOK_SECRET, &[(&ann, &RUNS)]);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(hook.executions.all().is_empty());
    }

    /// A secret issued by someone other than the publisher fails authentication,
    /// leaving no execution saved and no audit event recorded.
    #[test]
    fn a_secret_issued_by_someone_other_than_the_publisher_starts_nothing() {
        let ann = person("ann@corp.test");
        let sam = person("sam@corp.test");
        let hook = Hook::published_by(&ann, &sam);

        let result = hook.call_with(HOOK_SECRET, &[(&ann, &RUNS)]);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(hook.executions.all().is_empty());
        assert!(hook.records().is_empty());
    }

    /// A valid webhook secret cannot start a run for a missing publisher. The
    /// refusal names the publisher's run rights, saves no execution and is audited.
    #[test]
    fn a_publisher_who_left_does_not_have_their_webhook_run() {
        let ann = person("ann@corp.test");
        let hook = Hook::published_by(&ann, &ann);

        let outcome = hook.call_with(HOOK_SECRET, &[]).unwrap();

        assert_eq!(
            outcome,
            TriggeredStart::Refused(StartRefusal::PersonMayNotRun)
        );
        assert!(hook.executions.all().is_empty());
        assert_eq!(hook.records(), ["workflows.start_refused"]);
    }
}
