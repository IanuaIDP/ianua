//! Agent flows: stages of agent runs a person makes and starts at once.
//!
//! A flow is a workflow of one published version, started by hand as it is
//! made. Its one run is its progress. Lists and reads of designed workflows
//! leave flows out; these use cases list, read, stop and delete them.

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::execution::{
    ExecutionStatus, ExecutionView, WorkflowExecution,
};
use ianua_domain::isolation::scope::ResolvedTenant;

pub(crate) mod cancel;
pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod get;
pub(crate) mod list;

/// A flow just made, and its run, started at once.
pub struct FlowStarted {
    /// The flow, its one version.
    pub flow: Workflow<ResolvedTenant>,
    /// Its run, acting for the person who made it.
    pub run: WorkflowExecution<ResolvedTenant>,
}

/// A flow and its run, as a viewer may read it.
pub struct FlowProgress {
    /// The flow, its one version.
    pub flow: Workflow<ResolvedTenant>,
    /// Its run, with data above the viewer's clearance withheld.
    pub run: ExecutionView<ResolvedTenant>,
}

/// A flow and what its reader is shown of its run: a listed flow, or one
/// just stopped.
pub struct FlowStanding {
    /// The flow, its one version.
    pub flow: Workflow<ResolvedTenant>,
    /// What the reader is shown of its run.
    pub run: RunShown,
}

/// What a reader is shown of a flow's run.
pub enum RunShown {
    /// The run, with data above the reader's clearance withheld.
    Viewed(Box<ExecutionView<ResolvedTenant>>),
    /// Only where the run stands: the reader may not view workflows, as the
    /// maker who stops their own flow with the right to run them alone.
    StatusOnly(ExecutionStatus),
    /// No run is kept for the flow, as when its start failed halfway.
    Missing,
}

impl RunShown {
    /// `run` as `reader` may read it: whole, with data above their
    /// clearance withheld, or only where it stands when they may not view
    /// workflows.
    pub(crate) fn to(reader: WorkflowControl<'_>, run: WorkflowExecution<ResolvedTenant>) -> Self {
        let status = run.status();
        run.viewed_by(reader)
            .map_or(Self::StatusOnly(status), |view| {
                Self::Viewed(Box::new(view))
            })
    }
}

pub use cancel::{CancelPorts, CancelUseCase};
pub use create::{CreatePorts, CreateRequest, CreateUseCase};
pub use delete::{DeletePorts, DeleteUseCase};
pub use get::{GetPorts, GetUseCase};
pub use list::{ListPorts, ListUseCase};
