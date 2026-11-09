//! An agent asking a person for a delegation.

pub(crate) mod approve;
pub(crate) mod deny;
pub(crate) mod list;
pub(crate) mod request;

pub use approve::{ApproveRequestPorts, ApproveRequestRequest, ApproveRequestUseCase};
pub use deny::{DenyRequestPorts, DenyRequestRequest, DenyRequestUseCase};
pub use list::{ListRequestsPorts, ListRequestsUseCase, RequestsOf};
pub use request::{AskingAgent, RequestPorts, RequestRequest, RequestUseCase};

/// What a person is told when their answer lost to another one saved since
/// they read the request.
const ANSWERED_MEANWHILE: &str = "the request was answered by someone else meanwhile";
