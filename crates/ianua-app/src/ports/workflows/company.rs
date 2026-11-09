//! The company's own steps: what a workflow run hands the platform when one
//! of its steps acts on the tenant itself.

use async_trait::async_trait;
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;

/// One company step about to be made.
pub struct CompanyCall<'a> {
    /// The person the run acts for, coming through the run: every action
    /// asks again what they hold, and is refused once the run has ended.
    pub caller: &'a CallerContext,
    /// Records what the step did, as that person through the run, each
    /// record continuing the run's chain.
    pub auditor: &'a RequestAuditor,
    /// The call, with the step's inputs.
    pub call: &'a ActionCall,
}

/// Makes the company's own steps, each the action a person could take from
/// the dashboard.
///
/// Pat's workflow suspends Lee. The step is the dashboard's own suspension,
/// made as Pat through the run, so it is refused the moment Pat could not
/// do it by hand.
#[async_trait]
pub trait CompanySteps: Send + Sync {
    /// How `call` went: succeeded with what it read or changed, failed with
    /// the refusal in its own words, or turned away when nothing was done
    /// and trying again may go through.
    async fn run(&self, call: CompanyCall<'_>) -> ActionOutcome;
}
