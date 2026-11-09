//! Proxy pipelines: configuring, renaming, switching on and off, reading and
//! deleting them.

pub(crate) mod activate;
pub(crate) mod configure;
pub(crate) mod delete;
pub(crate) mod disable;
pub(crate) mod get;
pub(crate) mod list;
pub(crate) mod rename;

pub use activate::{ActivatePorts, ActivateUseCase};
pub use configure::{ConfigurePorts, ConfigureUseCase};
pub use delete::{DeletePorts, DeleteUseCase};
pub use disable::{DisablePorts, DisableUseCase};
pub use get::{GetPorts, GetUseCase};
pub use list::{ListPorts, ListUseCase, WithUsage};
pub use rename::{RenamePorts, RenameRequest, RenameUseCase};
