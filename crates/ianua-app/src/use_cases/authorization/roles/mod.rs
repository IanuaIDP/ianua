//! Roles: creating them, changing them and handing them out.

pub(crate) mod assign;
pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod get;
pub(crate) mod list;
pub(crate) mod revoke;
pub(crate) mod update;

pub use assign::{AssignPorts, AssignRequest, AssignUseCase};
pub use create::{CreatePorts, CreateRequest, CreateUseCase};
pub use delete::{DeletePorts, DeleteRequest, DeleteUseCase};
pub use get::{GetPorts, GetUseCase};
pub use list::{ListPorts, ListRequest, ListUseCase, WithAssignments};
pub use revoke::{RevokePorts, RevokeRequest, RevokeUseCase};
pub use update::{UpdatePorts, UpdateRequest, UpdateUseCase};
