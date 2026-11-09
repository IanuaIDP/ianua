//! The tenant's groups, written over LDAP by the person a connection is
//! bound as: adding, renaming and removing them, and changing who is in
//! them.
//!
//! Each write is the dashboard's own use case, asked with the person's own
//! rights, so the same domain checks decide it, the granter check among
//! them.

pub(crate) mod add;
pub(crate) mod add_member;
pub(crate) mod remove;
pub(crate) mod remove_member;
pub(crate) mod rename;

pub use add::{AddDirectoryPorts, AddDirectoryUseCase};
pub use add_member::{AddDirectoryMemberPorts, AddDirectoryMemberUseCase};
pub use remove::{RemoveDirectoryPorts, RemoveDirectoryUseCase};
pub use remove_member::{RemoveDirectoryMemberPorts, RemoveDirectoryMemberUseCase};
pub use rename::{RenameDirectoryPorts, RenameDirectoryUseCase};
