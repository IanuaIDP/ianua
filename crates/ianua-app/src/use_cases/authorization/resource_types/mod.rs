//! The resource types a tenant declares for its own permissions.

pub(crate) mod declare;
pub(crate) mod delete;
pub(crate) mod list;
pub(crate) mod update;

pub use declare::{DeclarePorts, DeclareRequest, DeclareUseCase};
pub use delete::{DeletePorts, DeleteUseCase};
pub use list::{ListPorts, ListRequest, ListUseCase};
pub use update::{UpdatePorts, UpdateRequest, UpdateUseCase};
