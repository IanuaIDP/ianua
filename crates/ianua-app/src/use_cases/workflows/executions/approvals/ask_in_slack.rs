//! Asking an open approval in a Slack channel too.
//!
//! Bob approves payments from Slack. When the workflow's approval step
//! opens, this posts its summary to the finance channel with Approve and
//! Deny buttons. The buttons only open the approval in the dashboard: a
//! press counts once Bob has signed in there and decided, under every rule
//! an approval keeps. Slack carries the question, never the answer.
//!
//! The post is the `workflow.ask_in_slack` job, queued with the approval in
//! the unit of work that opened it. A post Slack refuses, or an account no
//! longer there, is logged and left: the approval stays open in the
//! platform's inbox either way, so Slack being down never holds it up.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::data::{FieldName, FlowData};
use ianua_domain::domains::workflows::design::also_ask::{AlsoAsk, SlackAsk};
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::execution::{ActionCall, WorkflowExecution};
use ianua_domain::domains::workflows::integration::{ActionAccount, IntegrationKey, OperationKey};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::types::{
    ActionCallId, ActionClass, DeclaredAction, HttpsUrl, TenantId, WorkflowExecutionId,
};
use serde::{Deserialize, Serialize};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SealedAt;
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::ports::workflows::{
    ActionRunner, CallCredential, IntegrationAccountStore, WorkflowExecutionStore,
};
use crate::services::lookup::{existing_organization, existing_tenant};
use crate::tenancy::ScopedTenant;
use crate::use_cases::scheduling::{Handled, JobHandler, payload_of};
use crate::use_cases::workflows::accounts::connect::integration_credential_place;

/// The job type that asks an open approval in Slack.
pub(crate) const ASK_IN_SLACK_JOB: &str = "workflow.ask_in_slack";

/// The integration the question is posted through.
const SLACK: &str = "slack";

/// One open approval to ask in Slack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AskInSlackJob {
    /// The tenant the execution belongs to.
    pub tenant_id: TenantId,
    /// The execution waiting for approval.
    pub execution_id: WorkflowExecutionId,
    /// The approval step, by its key.
    pub step: String,
}

/// The ports [`AskInSlackUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AskInSlackPorts {
    /// The tenant's executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// The tenant's connected accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Makes the call to Slack.
    pub action_runner: Arc<dyn ActionRunner>,
    /// The tenant's slug, for the approval's address.
    pub tenants: Arc<dyn TenantStore>,
    /// The organization's slug, for the approval's address.
    pub organizations: Arc<dyn OrganizationStore>,
}

/// Posts an open approval's question to the Slack channel its step names.
pub struct AskInSlackUseCase {
    ports: AskInSlackPorts,
    dashboard: HttpsUrl,
}

impl AskInSlackUseCase {
    /// A use case posting through `ports`, its buttons opening approvals
    /// under `dashboard`.
    #[must_use]
    pub fn new(ports: AskInSlackPorts, dashboard: HttpsUrl) -> Self {
        Self { ports, dashboard }
    }

    /// Where the approval `step` of `execution` is decided in the
    /// dashboard.
    async fn approval_page(
        &self,
        tenant: &ScopedTenant,
        execution: &WorkflowExecution<ResolvedTenant>,
        step: &NodeKey,
    ) -> Result<String, AppError> {
        let tenant = existing_tenant(self.ports.tenants.as_ref(), tenant).await?;
        let organization =
            existing_organization(self.ports.organizations.as_ref(), tenant.organization_id())
                .await?;
        Ok(format!(
            "{}/organizations/{}/tenants/{}/workflows/runs/{}/approvals/{}",
            self.dashboard.as_str().trim_end_matches('/'),
            organization.slug().as_str(),
            tenant.slug().as_str(),
            execution.id(),
            step.as_str(),
        ))
    }

    /// Posts the question about `summary`, decided at `page`, to `ask`'s
    /// channel through its Slack account. A missing account, or one that is
    /// not Slack, posts nothing.
    async fn post(
        &self,
        tenant: &ScopedTenant,
        ask: &SlackAsk,
        summary: &str,
        page: &str,
    ) -> Result<(), AppError> {
        let account = self
            .ports
            .accounts
            .find_by_id(tenant, &ask.account())
            .await
            .or_internal()?
            .filter(|account| account.integration().as_str() == SLACK);
        let Some(account) = account else {
            tracing::warn!(account_id = %ask.account(), "the approval's Slack account is gone; nothing posted");
            return Ok(());
        };
        let call = slack_call(ask, summary, page).or_internal()?;
        let credential = SealedAt {
            secret: account.credential().clone(),
            place: integration_credential_place(tenant, account.id()),
        };
        let run = self
            .ports
            .action_runner
            .run(tenant, &call, CallCredential::Account(&credential))
            .await;
        if !matches!(run.outcome, ActionOutcome::Succeeded { .. }) {
            tracing::warn!(account_id = %ask.account(), "Slack did not take the approval's question");
        }
        Ok(())
    }
}

impl AskInSlackUseCase {
    /// Posts the approval `job` names to its step's Slack channel, while it
    /// is still open: an approval step's, or a loop's approval of every
    /// item. An execution that is gone, a step decided already, or one that
    /// asks nowhere else posts nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the execution, the account or the slugs
    ///   cannot be read, so the job tries again.
    pub async fn ask(&self, tenant: &ScopedTenant, job: AskInSlackJob) -> Result<(), AppError> {
        let Some(execution) = self
            .ports
            .executions
            .find_by_id(tenant, &job.execution_id)
            .await
            .or_internal()?
        else {
            return Ok(());
        };
        let Ok(step) = NodeKey::new(job.step) else {
            return Ok(());
        };
        let Some(approval) = execution.asked_at(&step) else {
            return Ok(());
        };
        let AlsoAsk::Slack(ask) = approval.also_ask() else {
            return Ok(());
        };
        let page = self.approval_page(tenant, &execution, &step).await?;
        self.post(tenant, ask, approval.summary().as_str(), &page)
            .await
    }
}

/// Runs ask-in-Slack jobs through [`AskInSlackUseCase`].
pub struct AskInSlackHandler {
    job_type: JobType,
    ask: Arc<AskInSlackUseCase>,
}

impl AskInSlackHandler {
    /// A handler posting through `ask`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(ask: Arc<AskInSlackUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(ASK_IN_SLACK_JOB)?;
        Ok(Self { job_type, ask })
    }
}

#[async_trait]
impl JobHandler for AskInSlackHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Posts the question; a store that cannot be read is tried again.
    async fn handle(&self, job: &ScheduledJob, _: &RequestAuditor) -> Result<Handled, AppError> {
        let payload: AskInSlackJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        self.ask.ask(&tenant, payload).await?;
        Ok(Handled::Done)
    }
}

/// The message to `channel`: the summary, and Approve and Deny buttons
/// opening `page`.
fn question(channel: &str, summary: &str, page: &str) -> Result<FlowData, DomainError> {
    let asked = FlowData::text(format!("Approval asked: {summary}"))?;
    let section = object(vec![
        ("type", FlowData::text("section")?),
        (
            "text",
            object(vec![
                ("type", FlowData::text("mrkdwn")?),
                ("text", asked.clone()),
            ])?,
        ),
    ])?;
    let buttons = object(vec![
        ("type", FlowData::text("actions")?),
        (
            "elements",
            FlowData::list(vec![
                button("Approve", "primary", &format!("{page}?decision=approve"))?,
                button("Deny", "danger", &format!("{page}?decision=deny"))?,
            ])?,
        ),
    ])?;
    object(vec![
        ("channel", FlowData::text(channel)?),
        ("text", asked),
        ("blocks", FlowData::list(vec![section, buttons])?),
    ])
}

/// A link button labelled `label` in `style`, opening `url`.
fn button(label: &str, style: &str, url: &str) -> Result<FlowData, DomainError> {
    object(vec![
        ("type", FlowData::text("button")?),
        (
            "text",
            object(vec![
                ("type", FlowData::text("plain_text")?),
                ("text", FlowData::text(label)?),
            ])?,
        ),
        ("style", FlowData::text(style)?),
        ("url", FlowData::text(url)?),
    ])
}

/// Workflow data of `fields`, by name.
fn object(fields: Vec<(&str, FlowData)>) -> Result<FlowData, DomainError> {
    let entries = fields
        .into_iter()
        .map(|(name, value)| Ok((FieldName::new(name)?, value)))
        .collect::<Result<Vec<_>, DomainError>>()?;
    FlowData::map(entries)
}

/// The call posting the question about `summary`, decided at `page`, to
/// `ask`'s channel.
fn slack_call(ask: &SlackAsk, summary: &str, page: &str) -> Result<ActionCall, DomainError> {
    Ok(ActionCall {
        call_id: ActionCallId::new(),
        integration: IntegrationKey::new(SLACK)?,
        operation: OperationKey::new("post-message")?,
        account: ActionAccount::Account(ask.account()),
        arguments: question(ask.channel().as_str(), summary, page)?,
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        exposure: DataClassLevel::Internal,
        origin: EventOrigin::Outside,
    })
}
