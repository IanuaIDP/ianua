//! How the organization's own dashboard and mail look: its logo, its color
//! and the name its mail goes out under.

pub(crate) mod change_org;
pub(crate) mod get_org;
mod lookup;
pub(crate) mod reset;

pub use change_org::{ChangeOrgPorts, ChangeOrgRequest, ChangeOrgUseCase};
pub use get_org::{GetOrgPorts, GetOrgUseCase};
pub use reset::{ResetOrgPorts, ResetOrgUseCase};
