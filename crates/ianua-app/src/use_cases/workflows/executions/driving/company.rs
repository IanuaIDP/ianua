//! Running a company step: one of the tenant's own actions, made as the
//! person the run acts for.
//!
//! The step becomes a caller of its own: that person, coming through this
//! run. Every action it takes asks again what they hold, so Pat's workflow
//! can do no more than Pat could by hand at that moment, and nothing once
//! the run has ended. Its records say the action was Pat's, through the
//! run, and an event it raises continues the run's chain, so a workflow it
//! sets off can never loop forever.

use std::sync::Arc;

use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::types::{HumanAccount, UntrustedText, WorkflowExecutionId};

use crate::context::{CallerContext, CallerIdentity, Credential};
use crate::ports::tenant::TenantStore;
use crate::ports::workflows::{CompanyCall, CompanySteps};
use crate::use_cases::workflows::executions::driving::Driving;

/// The ports a company step goes through.
#[derive(ianua_macros::Fakes)]
pub struct CompanyPorts {
    /// Makes the company's own steps, as the person a run acts for.
    pub steps: Arc<dyn CompanySteps>,
    /// Reads the tenant's organization, which a company step acts in.
    pub tenants: Arc<dyn TenantStore>,
}

/// Who a company step acts as: the person the run is for, through the run.
#[derive(Debug, Clone, Copy)]
pub(super) struct CompanyRun {
    /// The run.
    pub(super) execution: WorkflowExecutionId,
    /// The person it acts for.
    pub(super) person: HumanAccount,
}

impl Driving<'_> {
    /// How the company step `call` of `run` went.
    pub(super) async fn company_call(&self, run: CompanyRun, call: &ActionCall) -> ActionOutcome {
        let caller = match self.run_caller(run).await {
            Ok(caller) => caller,
            Err(unsent) => return unsent,
        };
        let auditor = self
            .auditor
            .recording_as(caller.audit_context())
            .from_execution(call.origin);
        self.ports
            .company
            .steps
            .run(CompanyCall {
                caller: &caller,
                auditor: &auditor,
                call,
            })
            .await
    }

    /// The person `run` acts for, as a caller coming through it, in the
    /// tenant's organization and under its plan. A tenant that cannot be
    /// read turns the call away unsent.
    async fn run_caller(&self, run: CompanyRun) -> Result<CallerContext, ActionOutcome> {
        let tenant_id = **self.tenant;
        let tenant = self
            .ports
            .company
            .tenants
            .find_by_id(&tenant_id)
            .await
            .map_err(unread)?
            .ok_or_else(|| failed("the tenant is gone"))?;
        let limits = self
            .ports
            .plan_limits
            .for_tenant(&tenant_id)
            .await
            .map_err(unread)?;
        let identity = match run.person {
            HumanAccount::User(user) => CallerIdentity::TenantUser(user),
            HumanAccount::OrgUser(member) => CallerIdentity::OrgUser(member),
        };
        CallerContext::new(
            identity,
            Credential::WorkflowRun(run.execution),
            *tenant.organization_id(),
            tenant_id,
            limits,
        )
        .map_err(|_| failed("the run's person cannot act through it"))
    }
}

/// A failure trying again would not change.
fn failed(reason: &str) -> ActionOutcome {
    ActionOutcome::Failed(UntrustedText::record(reason))
}

/// A read that did not answer: nothing was done, so the call is tried
/// again.
fn unread(error: impl std::fmt::Display) -> ActionOutcome {
    tracing::warn!(%error, "a company step could not read its tenant");
    ActionOutcome::TurnedAway(UntrustedText::record("the tenant could not be read"))
}
