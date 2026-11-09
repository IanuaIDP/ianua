//! The company's own steps, each made through the action a person takes
//! from the dashboard.
//!
//! Pat's workflow signs Lee out. The step lists Lee's sessions and ends
//! each with the dashboard's own actions, as Pat coming through the run.
//! Those actions check what Pat holds and record what they did, so a step
//! never decides anything about access by itself. A refusal fails the step
//! in the action's own words; a store that did not answer turns it away,
//! nothing kept, to be tried again, and trying again finds only what is
//! still left to do.

mod access;
mod agents;
mod inputs;
mod people;
mod platform;
mod reviews;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::company::CompanyOperation;
use ianua_domain::types::UntrustedText;

pub use self::access::AccessActions;
pub use self::agents::AgentActions;
pub use self::people::PeopleActions;
pub use self::platform::PlatformActions;
use crate::error::AppError;
use crate::ports::workflows::{CompanyCall, CompanySteps};
use crate::use_cases::notifications::notices::Offering;
use crate::use_cases::workflows::executions::answers::{data, failed};

/// The dashboard's actions the company steps are made through.
pub struct CompanyActions {
    /// People: reading, suspending, signing out, their factors and keys.
    pub people: PeopleActions,
    /// Groups, access requests and reviews.
    pub access: AccessActions,
    /// Agents and their runs.
    pub agents: AgentActions,
    /// Apps, the audit trail and classification rules.
    pub platform: PlatformActions,
}

/// Makes the company's own steps through the dashboard's actions.
pub struct CompanyStepRunner {
    actions: Arc<CompanyActions>,
}

impl CompanyStepRunner {
    /// A runner making steps through `actions`.
    #[must_use]
    pub fn new(actions: Arc<CompanyActions>) -> Self {
        Self { actions }
    }

    /// The step `operation` made for `step`, or why it went no further.
    // One arm per company step, so a step added to the domain without a way
    // to make it fails to compile here; splitting the match would lose that.
    #[allow(clippy::too_many_lines)]
    async fn made(
        &self,
        operation: CompanyOperation,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let (people, access) = (&self.actions.people, &self.actions.access);
        let (agents, platform) = (&self.actions.agents, &self.actions.platform);
        match operation {
            CompanyOperation::FindPerson => people.find(step).await,
            CompanyOperation::SuspendPerson => people.suspend(step).await,
            CompanyOperation::ResetTwoStep => people.reset_factors(step).await,
            CompanyOperation::SignOut => people.sign_out(step).await,
            CompanyOperation::RevokeKeys => people.revoke_keys(step).await,
            CompanyOperation::ForgetDevices => people.forget_devices(step).await,
            CompanyOperation::InvitePerson => people.invite(step).await,
            CompanyOperation::ListMembers => access.members(step).await,
            CompanyOperation::AddToGroup => access.add(step, people).await,
            CompanyOperation::RemoveFromGroup => access.remove(step, people).await,
            CompanyOperation::RemoveGroups => access.remove_everywhere(step, people).await,
            CompanyOperation::GrantAccess => access.grant(step, people).await,
            CompanyOperation::DecideRequest => access.decide(step).await,
            CompanyOperation::CheckAccess => access.check(step, people).await,
            CompanyOperation::BreakGlass => access.break_glass(step, people).await,
            CompanyOperation::OpenReview => access.open_review(step, people).await,
            CompanyOperation::SuggestReview => access.suggest(step, people).await,
            CompanyOperation::PauseAgent => agents.pause(step).await,
            CompanyOperation::EndAgentRun => agents.end_run(step).await,
            CompanyOperation::RevokeAgentTasks => agents.revoke_tasks(step).await,
            CompanyOperation::NarrowAgent => agents.narrow(step).await,
            CompanyOperation::AgentActions => agents.recent(step).await,
            CompanyOperation::ReadRequests => platform.requests(step).await,
            CompanyOperation::CloseApp => platform.close_app(step).await,
            CompanyOperation::AttackMode => platform.attack_mode(step).await,
            CompanyOperation::SearchAudit => platform.search_audit(step).await,
            CompanyOperation::MakeAuditPack => platform.make_audit_pack(step).await,
            CompanyOperation::ClassifyField => platform.classify(step).await,
            CompanyOperation::Notify => people.notify(step, Offering::Nothing).await,
            CompanyOperation::OfferAccess => people.offer_access(step).await,
            CompanyOperation::RemindUntilDecided => access.remind(step, people).await,
            CompanyOperation::PauseKey => people.pause_key(step).await,
            CompanyOperation::ResumeKey => people.resume_key(step).await,
            CompanyOperation::SendSignal => people.send_signal(step).await,
            CompanyOperation::HideFields => platform.hide_fields(step).await,
            CompanyOperation::Allow => Ok(verdict(step, "allow")),
            CompanyOperation::Refuse => Ok(verdict(step, "refuse")),
        }
    }
}

#[async_trait]
impl CompanySteps for CompanyStepRunner {
    async fn run(&self, step: CompanyCall<'_>) -> ActionOutcome {
        let Some(operation) = CompanyOperation::named(&step.call.operation) else {
            return failed("the company offers no such step");
        };
        match self.made(operation, &step).await {
            Ok(outcome) | Err(outcome) => outcome,
        }
    }
}

/// A "before" run's decision, `allow` or `refuse`, handed on as `verdict`:
/// the change waiting on the run reads it from the step having succeeded.
fn verdict(step: &CompanyCall<'_>, said: &str) -> ActionOutcome {
    match data(vec![("verdict", FlowData::text(said))]) {
        Ok(output) => succeeded(step, output, DataClassLevel::Internal),
        Err(refused) => refused,
    }
}

/// The step succeeded with `output`, as sensitive as its inputs were or as
/// `level`, whichever is more.
pub(super) fn succeeded(
    step: &CompanyCall<'_>,
    output: FlowData,
    level: DataClassLevel,
) -> ActionOutcome {
    ActionOutcome::Succeeded {
        output,
        exposure: step.call.exposure.max(level),
    }
}

/// What an action's refusal makes of the step: a store or a limit that did
/// not answer turns it away, since nothing was kept; anything else fails it
/// in the action's own words, since trying again would find the same.
pub(super) fn unmade(error: AppError) -> ActionOutcome {
    match error {
        AppError::Internal(_) | AppError::TooManyRequests(_) | AppError::Busy => {
            tracing::warn!(%error, "a company step's action did not answer");
            ActionOutcome::TurnedAway(UntrustedText::record("the platform did not answer"))
        }
        AppError::Unauthenticated => {
            failed("the run has ended, or its person may no longer act through it")
        }
        AppError::Domain(error) => error.refusal().map_or_else(
            || failed("the action was refused"),
            |refusal| failed(refusal.as_str()),
        ),
        AppError::NotFound(refusal)
        | AppError::Forbidden(refusal)
        | AppError::Conflict(refusal)
        | AppError::TenantUnavailable(refusal)
        | AppError::LinkExpired(refusal) => failed(refusal.as_str()),
        _ => failed("the action was refused"),
    }
}
