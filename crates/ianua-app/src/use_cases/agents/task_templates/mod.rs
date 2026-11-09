//! Reusable task templates.

pub(crate) mod decide;
pub(crate) mod get;
pub(crate) mod list;
pub(crate) mod propose;

pub use decide::{DecidePorts, DecideRequest, DecideUseCase, TemplateDecision};
pub use get::{GetPorts, GetUseCase};
pub use list::{ListPorts, ListUseCase};
pub use propose::{ProposePorts, ProposeRequest, ProposeUseCase};
