//! What a person deciding a run's held call is told: where the run stands,
//! and nothing of what it read or called.

use ianua_domain::domains::agents::execution::run::{AgentRun, RunStatus};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AgentRunId;

/// Where a run stands once a person decided the call it held: all a
/// decision hands back. Approving a call takes only the right to approve,
/// and a run shows its goal, every call and what each returned, so the
/// person deciding reads the run through
/// [`get_run`](crate::use_cases::agents::runs::reading::readers::get) like anyone else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunDecided {
    /// The execution whose held call was decided.
    pub run_id: AgentRunId,
    /// Where it stands now.
    pub status: RunStatus,
}

impl RunDecided {
    /// Where `run` stands.
    pub(in crate::use_cases::agents::runs) fn of(run: &AgentRun<ResolvedTenant>) -> Self {
        Self {
            run_id: *run.id(),
            status: run.status(),
        }
    }
}
