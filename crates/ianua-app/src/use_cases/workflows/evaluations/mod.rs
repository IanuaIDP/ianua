//! Evaluations: an author saves a workflow's sample cases, starts an
//! evaluation of its draft, and reads back what each case came to; a
//! worker runs the cases as test runs, a few at a time, as
//! `workflow.evaluate` jobs; and two sweeps end evaluations whose looks
//! were lost and purge those past their keeping.

pub(crate) mod end_overdue;
pub(crate) mod get;
pub(crate) mod get_set;
pub(crate) mod list;
mod lookup;
pub(crate) mod purge;
pub(crate) mod run;
pub(crate) mod save_set;
pub(crate) mod start;

pub use end_overdue::{EndOverduePorts, EndOverdueUseCase, OverdueReport};
pub use get::{GetPorts, GetRequest, GetUseCase};
pub use get_set::{GetSetPorts, GetSetRequest, GetSetUseCase};
pub use list::{ListPorts, ListRequest, ListUseCase};
pub use purge::{PurgeEndedPorts, PurgeEndedUseCase};
pub use run::{
    EvaluationHandler, EvaluationTry, EvaluationTurn, Evaluations, RunPorts, RunRequest, RunUseCase,
};
pub use save_set::{SaveSetPorts, SaveSetRequest, SaveSetUseCase};
pub use start::{StartPorts, StartRequest, StartUseCase};
