//! A tenant user moving their account to a new address.

pub(crate) mod cancel;
pub(crate) mod change;
pub(crate) mod confirm;
pub(crate) mod links;
pub(crate) mod request;
pub(crate) mod resend;
pub(crate) mod status;
pub(in crate::use_cases::identity) mod tenant;

pub use cancel::{CancelChangePorts, CancelChangeUseCase};
pub use change::{ChangePorts, ChangeRequest, ChangeUseCase};
pub use confirm::{ConfirmChangePorts, ConfirmChangeUseCase};
pub use links::EmailChangePolicy;
pub use request::{RequestChangePorts, RequestChangeRequest, RequestChangeUseCase};
pub use resend::{ResendChangePorts, ResendChangeRequest, ResendChangeUseCase};
pub use status::{ChangeStatusPorts, ChangeStatusUseCase};
