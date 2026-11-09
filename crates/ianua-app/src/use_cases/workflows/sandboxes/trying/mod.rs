//! Trials: a person hands a built sandbox version sample input, a worker
//! runs it as a code step would, and they read back how it went. Ended
//! trials are purged once past their keeping.

pub(crate) mod get;
mod lookup;
pub(crate) mod purge;
pub(crate) mod run;
pub(crate) mod start;

pub use get::{GetTrialPorts, GetTrialRequest, GetTrialUseCase};
pub use purge::{PurgeEndedTrialsPorts, PurgeEndedTrialsUseCase};
pub use run::{
    RunTrialPorts, RunTrialRequest, RunTrialUseCase, SandboxTrials, TrialHandler, TrialTry,
    TrialTurn,
};
pub use start::{StartTrialPorts, StartTrialRequest, StartTrialUseCase};
