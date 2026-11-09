//! Roles, who holds them, and deleting one with its holders moved: the
//! stores of `ports/authorization/roles.rs`.

pub(crate) mod assignments;
pub(crate) mod definitions;

pub use assignments::{PgRoleAssignmentStore, PgRoleDeletionUnitOfWork, PgRoleHolderQueries};
pub use definitions::PgRoleStore;
