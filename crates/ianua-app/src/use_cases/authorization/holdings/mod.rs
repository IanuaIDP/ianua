//! Who holds what: reading a principal's access, the permissions it holds
//! for the gateway, and a role's holders, and the sweep that clears away
//! holdings whose end has passed, or a grant giving one of them again.

pub(crate) mod expire;
pub(crate) mod get_principal_access;
pub(crate) mod lapsed;
pub(crate) mod list_role_holders;

pub use expire::{ExpirePorts, ExpireUseCase};
pub use get_principal_access::{
    DirectMembership, DirectRole, GetPrincipalAccessPorts, GetPrincipalAccessUseCase,
    PrincipalAccess, RoleThroughGroup,
};
pub use list_role_holders::{ListRoleHoldersPorts, ListRoleHoldersRequest, ListRoleHoldersUseCase};
