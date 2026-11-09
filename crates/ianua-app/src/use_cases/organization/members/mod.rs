//! The organization's members: their accounts, roles, tenant access and linked identities.

/// A member's account: created, read, changed, removed.
pub(crate) mod accounts;
/// A member's password and second factor, changed or reset.
pub(crate) mod credentials;
/// Accounts a member links to sign in with.
pub(crate) mod identities;
/// What a member may do: role, tenant access, ownership.
pub(crate) mod rights;

pub use accounts::{
    ChangeOrgUserDisplayNamePorts, ChangeOrgUserDisplayNameRequest,
    ChangeOrgUserDisplayNameUseCase, ChangeOrgUserEmailPorts, ChangeOrgUserEmailRequest,
    ChangeOrgUserEmailUseCase, CreateOrgUserPorts, CreateOrgUserRequest, CreateOrgUserResult,
    CreateOrgUserUseCase, DeleteOrgUserPorts, DeleteOrgUserUseCase, GetOrgMePorts, GetOrgMeUseCase,
    ListOrgUsersPorts, ListOrgUsersRequest, ListOrgUsersUseCase, OrgMe,
    UpdateOrgUserPreferencesPorts, UpdateOrgUserPreferencesRequest,
    UpdateOrgUserPreferencesUseCase, UpdateOrgUserStatusPorts, UpdateOrgUserStatusRequest,
    UpdateOrgUserStatusUseCase,
};
pub use credentials::{
    ChangeOrgUserPasswordPorts, ChangeOrgUserPasswordRequest, ChangeOrgUserPasswordUseCase,
    ResetMfaPorts, ResetMfaUseCase, ResetOrgUserPasswordPorts, ResetOrgUserPasswordRequest,
    ResetOrgUserPasswordUseCase, ResetPasswordResult,
};
pub use identities::{
    LinkIdentityPorts, LinkIdentityUseCase, LinkingPerson, UnlinkIdentityPorts,
    UnlinkIdentityRequest, UnlinkIdentityUseCase, Unlinker,
};
pub use rights::{
    ChangeOrgUserRolePorts, ChangeOrgUserRoleRequest, ChangeOrgUserRoleUseCase,
    GetOrgUserAccessPorts, GetOrgUserAccessUseCase, ListGrantableRolesPorts,
    ListGrantableRolesRequest, ListGrantableRolesUseCase, OrgUserAccess,
    SetOrgUserTenantAccessPorts, SetOrgUserTenantAccessRequest, SetOrgUserTenantAccessUseCase,
    TenantAccess, TransferOwnershipPorts, TransferOwnershipRequest, TransferOwnershipUseCase,
    WhoseReach,
};
