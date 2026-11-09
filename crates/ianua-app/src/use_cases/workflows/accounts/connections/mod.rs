//! Connecting an account by signing in at the integration's service: a
//! person begins, the service answers at the platform's one callback
//! address, the person finishes with the one-time code their browser
//! brought back, and a sweep removes the connections nobody finished.

pub(crate) mod answer;
pub(crate) mod begin;
pub(crate) mod finish;
mod lookup;
pub(crate) mod sweep;

pub use answer::{AnswerPorts, AnswerRequest, AnswerUseCase, Answered};
pub use begin::{BeginPorts, BeginUseCase, Begun};
pub use finish::{FinishPorts, FinishRequest, FinishUseCase};
pub use sweep::{SweepPorts, SweepUseCase};
