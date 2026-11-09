//! SAML apps: the outside services a tenant's people sign in to, with this
//! platform as their identity provider. Adding, reading, changing,
//! switching and removing them.

pub(crate) mod change_status;
pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod get;
pub(crate) mod list;
pub(crate) mod update;

pub use change_status::{ChangeStatusPorts, ChangeStatusRequest, ChangeStatusUseCase};
pub use create::{CreatePorts, CreateRequest, CreateUseCase};
pub use delete::{DeletePorts, DeleteUseCase};
pub use get::{GetPorts, GetUseCase};
pub use list::{ListPorts, ListUseCase};
pub use update::{UpdatePorts, UpdateRequest, UpdateUseCase};
