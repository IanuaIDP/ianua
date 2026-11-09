//! A policy's versions: drafted, reviewed, activated, read.

pub(crate) mod change_status;
pub(super) mod draft_edit;
pub(crate) mod get;
pub(crate) mod list;
pub(crate) mod start_draft;

pub use change_status::{ChangeStatusPorts, ChangeStatusUseCase, Transition};
pub use get::{GetVersionPorts, GetVersionUseCase};
pub use list::{ListVersionsPorts, ListVersionsUseCase};
pub use start_draft::{StartDraftPorts, StartDraftUseCase};
