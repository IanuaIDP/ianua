//! The tenant's users, written over LDAP by the person a connection is
//! bound as: adding, renaming, readdressing and removing them, and
//! Password-Modify.
//!
//! Each write is the dashboard's own use case, asked with the person's own
//! rights, so the same domain checks decide it.

pub(crate) mod add;
pub(crate) mod change_email;
pub(crate) mod change_password;
pub(crate) mod remove;
pub(crate) mod rename;

pub use add::{AddDirectoryPorts, AddDirectoryUseCase, NewDirectory};
pub use change_email::{
    ChangeDirectoryEmailPorts, ChangeDirectoryEmailUseCase, DirectoryEmailChange,
};
pub use change_password::{
    ChangeDirectoryPasswordPorts, ChangeDirectoryPasswordUseCase, DirectoryPasswordChange,
};
pub use remove::{RemoveDirectoryPorts, RemoveDirectoryUseCase};
pub use rename::{RenameDirectoryPorts, RenameDirectoryUseCase};
