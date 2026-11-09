//! Plan account checks: an integration account switched off, or changed
//! so it may lend itself to fewer people or steps, becomes one job checking
//! the versions in service that act through it, keyed by the event, so a
//! repeated delivery of the event checks nothing twice.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::scheduling::job_key::KeyHold;
use ianua_domain::shared::clock;
use ianua_domain::types::event_type::{EventType, WorkflowsEvent};
use ianua_domain::types::{AuditRecordId, IntegrationAccountId, TenantId};
use uuid::Uuid;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::scheduling::{Enqueued, JobQueue};
use crate::ports::shared::PublishedEvent;
use crate::use_case::Command;
use crate::use_cases::scheduling::{NewJob, PlanReport, key_of};
use crate::use_cases::workflows::published::holds::check::{AccountCheckJob, CHECK_ACCOUNT_JOB};

/// Where account check jobs are queued, and how many tries each gets.
#[derive(Clone)]
pub struct AccountChecks {
    /// Persists rechecks of workflows using a changed connected account.
    pub queue: Arc<dyn JobQueue>,
    /// Tries a check gets before it is given up.
    pub attempts: NonZeroU32,
}

impl AccountChecks {
    /// Queues the check of `account` of `tenant_id` the event `record_id`
    /// asks for, once for that event.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be built or queued.
    async fn queue(
        &self,
        tenant_id: TenantId,
        account: IntegrationAccountId,
        record_id: AuditRecordId,
    ) -> Result<Enqueued, AppError> {
        NewJob {
            job_type: CHECK_ACCOUNT_JOB,
            payload: &AccountCheckJob { tenant_id, account },
            tenant_id,
            key: key_of(record_id, account)?,
            hold: KeyHold::WhileKept,
            run_at: clock::now(),
            attempts: self.attempts,
        }
        .queue(self.queue.as_ref())
        .await
    }
}

/// The ports [`PlanAccountChecksUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanAccountChecksPorts {
    /// Where checks are queued.
    pub jobs: AccountChecks,
}

/// Plans the checks an account's change means.
///
/// The event pipeline runs it, for nobody, so its caller is `()`.
pub struct PlanAccountChecksUseCase {
    ports: PlanAccountChecksPorts,
}

impl PlanAccountChecksUseCase {
    /// A planner over `ports`.
    #[must_use]
    pub fn new(ports: PlanAccountChecksPorts) -> Self {
        Self { ports }
    }
}

impl Command for PlanAccountChecksUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<PlanReport, AppError>;

    /// Queues one check of the account a tenant's `workflows.account_disabled`
    /// or `workflows.account_changed` names. Any other event plans nothing.
    /// Records nothing: the check records each version it holds.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the job cannot be queued. The pipeline
    /// delivers the event again, and what was queued is not queued twice.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<PlanReport, AppError> {
        let Some(tenant_id) = event.event.tenant_id().copied() else {
            return Ok(PlanReport::default());
        };
        let Some(account) = narrowed_account(&event) else {
            return Ok(PlanReport::default());
        };
        let enqueued = self.ports.jobs.queue(tenant_id, account, event.id).await?;
        Ok(PlanReport::default().counting(enqueued))
    }
}

/// The account `event` says was switched off or changed, or none for any
/// other event.
fn narrowed_account(event: &PublishedEvent) -> Option<IntegrationAccountId> {
    let EventType::Workflows(WorkflowsEvent::AccountDisabled | WorkflowsEvent::AccountChanged) =
        event.event.event_type()
    else {
        return None;
    };
    let payload = event.event.payload();
    let id = Uuid::parse_str(payload.get("account")?).ok()?;
    Some(IntegrationAccountId::from_uuid(id))
}
