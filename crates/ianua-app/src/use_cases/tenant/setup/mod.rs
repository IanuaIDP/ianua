//! A new tenant's setup: planned when the tenant is announced as
//! provisioned, picked up again by the reconcile sweep when it never began
//! or stalled, run one step per job, and failed at a step whose tries are
//! spent.

mod fail;
mod job;
mod lookup;
mod plan;
mod run;
mod start;

pub use fail::{FailStepPorts, FailStepUseCase};
pub use job::{SETUP_STEP_JOB, SetupStepHandler, SetupSteps};
pub use plan::{PlanPorts, PlanUseCase};
pub use run::{RunStepPorts, RunStepUseCase};
pub(crate) use start::SetupStart;
