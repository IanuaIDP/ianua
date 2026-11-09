//! Check an account: every version in service acting through an account
//! that just changed is checked against it, and each that can no longer
//! use it for its publisher is held, recorded and so told to the people
//! who wrote it.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::domains::workflows::design::workflow::{Hold, MissingAccount, Workflow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, IntegrationAccountId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{IntegrationAccountStore, WorkflowStore};
use crate::services::account_now::AccountsNow;
use crate::services::holds::{AccountReads, missing_account, publisher_now};
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::scheduling::{Handled, JobHandler, done_unless_failed, payload_of};

/// The job type that checks the versions acting through one account.
pub(crate) const CHECK_ACCOUNT_JOB: &str = "workflow.check_account";

/// What an account check job carries: which account of which tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct AccountCheckJob {
    pub(super) tenant_id: TenantId,
    pub(super) account: IntegrationAccountId,
}

/// The ports [`CheckAccountUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CheckAccountPorts {
    /// The versions, for those in service using the account.
    pub workflows: Arc<dyn WorkflowStore>,
    /// The accounts they act through.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// What publishers and owners hold now.
    pub accounts_now: Arc<AccountsNow>,
    /// Keeps each hold and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Holds the versions an account no longer serves.
pub struct CheckAccountUseCase {
    ports: CheckAccountPorts,
}

impl CheckAccountUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CheckAccountPorts) -> Self {
        Self { ports }
    }

    /// The account `workflow` can no longer use for its publisher, or none
    /// when it still can, or its publisher can act no more, which starting
    /// it refuses on its own.
    async fn missing_in(
        &self,
        tenant: &ScopedTenant,
        workflow: &Workflow<ResolvedTenant>,
    ) -> Result<Option<MissingAccount>, AppError> {
        let Some(publisher) = publisher_now(&self.ports.accounts_now, tenant, workflow).await?
        else {
            return Ok(None);
        };
        let reads = AccountReads {
            accounts: self.ports.accounts.as_ref(),
            people: &self.ports.accounts_now,
        };
        missing_account(reads, tenant, workflow, &publisher).await
    }

    /// Holds `workflow` for want of `missing` and records it, together.
    async fn hold(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        mut workflow: Workflow<ResolvedTenant>,
        missing: MissingAccount,
    ) -> Result<(), AppError> {
        workflow.hold_for(missing).map_err(AppError::from_domain)?;
        kept_together(self.ports.unit_of_work.as_ref(), async {
            self.ports
                .workflows
                .save(tenant, &workflow)
                .await
                .or_internal()?;
            auditor
                .dispatch_by(&ActorRef::System, workflow.take_events(tenant))
                .await
                .or_internal()
        })
        .await
    }
}

impl Command for CheckAccountUseCase {
    type Caller = ScopedTenant;
    type Input = IntegrationAccountId;
    type Output = Result<u32, AppError>;

    /// Checks every version in service acting through `account`, holds each
    /// that can no longer use it for its publisher, recording
    /// `workflows.version_held`, and says how many it held. A version
    /// already held stays as it was.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the versions, an account or someone's
    /// records cannot be read, or a hold cannot be kept; the job is tried
    /// again, and a version held already is not held twice.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        account: IntegrationAccountId,
    ) -> Result<u32, AppError> {
        let versions = self
            .ports
            .workflows
            .list_published_using(tenant, &account)
            .await
            .or_internal()?;
        let mut held = 0_u32;
        for workflow in versions {
            if workflow.hold() != &Hold::Clear {
                continue;
            }
            let Some(missing) = self.missing_in(tenant, &workflow).await? else {
                continue;
            };
            self.hold(tenant, auditor, workflow, missing).await?;
            held = held.saturating_add(1);
        }
        Ok(held)
    }
}

/// Runs account check jobs through [`CheckAccountUseCase`].
pub struct CheckAccountHandler {
    job_type: JobType,
    check: Arc<CheckAccountUseCase>,
}

impl CheckAccountHandler {
    /// A handler checking accounts through `check`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the job type is not one,
    /// which it always is.
    pub fn new(check: Arc<CheckAccountUseCase>) -> Result<Self, DomainError> {
        let job_type = JobType::new(CHECK_ACCOUNT_JOB)?;
        Ok(Self { job_type, check })
    }
}

#[async_trait]
impl JobHandler for CheckAccountHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Checks the account's versions in its tenant.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let payload: AccountCheckJob = payload_of(job)?;
        let tenant = ScopedTenant::for_background(payload.tenant_id);
        let auditor = auditor.with_tenant(payload.tenant_id);
        done_unless_failed(self.check.execute(&tenant, &auditor, payload.account).await)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::account::{AccountSharing, IntegrationAccount};
    use ianua_domain::domains::workflows::design::workflow::AccountUnusable;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::workflows::{
        FakeIntegrationAccountStore, FakeWorkflowStore, accounts_now_of, append_step, draft_by,
        managing, person, published_by, sheets_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const LENDS: [SystemPermission; 2] = [
        SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
        SystemPermission::Workflows(WorkflowAction::Run),
    ];

    /// Bob's weekly report, appending through `account`, in service.
    fn report_by(
        bob: &Human,
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> Workflow<ResolvedTenant> {
        published_by(
            bob,
            draft_by(bob, vec![append_step("append", *account.id())], Vec::new()),
        )
    }

    /// What checking `account` came to, and what it recorded.
    fn checked(
        account: &IntegrationAccount<ResolvedTenant>,
        versions: &Arc<FakeWorkflowStore>,
        people: &[(&Human, &[SystemPermission])],
    ) -> (u32, Vec<String>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = CheckAccountUseCase::new(CheckAccountPorts {
            workflows: versions.clone(),
            accounts: Arc::new(FakeIntegrationAccountStore::holding(account)),
            accounts_now: Arc::new(accounts_now_of(people)),
            ..CheckAccountPorts::fakes()
        });
        let held = block_on(use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(sink.clone()),
            *account.id(),
        ))
        .unwrap();
        let records = sink.records.lock().unwrap().clone();
        (held, records)
    }

    /// Ann shared her sheets account and Bob's report appends through it.
    /// Ann keeps it to herself: Bob's report is held, saying the step
    /// needs an account it is no longer lent, and recorded once.
    #[test]
    fn a_version_whose_account_is_no_longer_lent_is_held() {
        let ann = person("ann@corp.test");
        let bob = person("bob@corp.test");
        let mut account = sheets_account(&ann, AccountSharing::Tenant);
        let report = report_by(&bob, &account);
        account.keep_to_owner(&managing(&ann)).unwrap();
        let versions = Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(&report)));

        let (held, records) = checked(&account, &versions, &[(&ann, &LENDS), (&bob, &LENDS)]);

        let kept = block_on(versions.find_published(&test_ctx().tenant(), report.id()))
            .unwrap()
            .unwrap();
        assert_eq!(held, 1);
        assert!(matches!(
            kept.hold(),
            Hold::NeedsAccount(missing) if missing.why == AccountUnusable::NotLent
        ));
        assert_eq!(records, ["workflows.version_held"]);
    }

    /// Ann's own report through her account kept to herself still runs:
    /// nothing is held and nothing recorded.
    #[test]
    fn a_version_its_account_still_serves_is_left_alone() {
        let ann = person("ann@corp.test");
        let account = sheets_account(&ann, AccountSharing::OwnerOnly);
        let report = report_by(&ann, &account);
        let versions = Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(&report)));

        let (held, records) = checked(&account, &versions, &[(&ann, &LENDS)]);

        assert_eq!(held, 0);
        assert!(records.is_empty());
    }
}
