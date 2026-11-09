//! A tenant's roles and permissions: the catalogue, making, changing and
//! removing roles, assigning them, and who holds them.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::roles::{
    AssignRole, Holder, NewAppRole, NewRole, PermissionArea, Role, RoleChange, RoleMade,
};

/// `GET …/authorization/roles`.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Page<Role>> {
    Request::of(Call::get(tenant.at("/authorization/roles")))
}

/// `GET …/authorization/roles/{id}`.
#[must_use]
pub fn get(tenant: &TenantPath, role_id: &str) -> Request<Role> {
    Request::of(Call::get(
        tenant.at(&format!("/authorization/roles/{role_id}")),
    ))
}

/// `POST …/authorization/roles`.
#[must_use]
pub fn create(tenant: &TenantPath, role: &NewRole) -> Request<RoleMade> {
    Request::of(Call::post(tenant.at("/authorization/roles")).json(role))
}

/// `POST …/authorization/roles` for a role granting permissions of the
/// tenant's own app.
#[must_use]
pub fn create_for_app(tenant: &TenantPath, role: &NewAppRole) -> Request<RoleMade> {
    Request::of(Call::post(tenant.at("/authorization/roles")).json(role))
}

/// `PATCH …/authorization/roles/{id}`.
#[must_use]
pub fn change(tenant: &TenantPath, role_id: &str, change: &RoleChange) -> Request<()> {
    let path = tenant.at(&format!("/authorization/roles/{role_id}"));
    Request::of(Call::patch(path).json(change))
}

/// `DELETE …/authorization/roles/{id}`.
#[must_use]
pub fn remove(tenant: &TenantPath, role_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/authorization/roles/{role_id}")),
    ))
}

/// `POST …/authorization/roles/{id}/assignments`: gives a user the role.
#[must_use]
pub fn assign(tenant: &TenantPath, role_id: &str, assign: &AssignRole) -> Request<()> {
    let path = tenant.at(&format!("/authorization/roles/{role_id}/assignments"));
    Request::of(Call::post(path).json(assign))
}

/// `DELETE …/authorization/roles/{id}/assignments/{user}`: takes it back.
#[must_use]
pub fn unassign(tenant: &TenantPath, role_id: &str, user_id: &str) -> Request<()> {
    let path = tenant.at(&format!(
        "/authorization/roles/{role_id}/assignments/{user_id}"
    ));
    Request::of(Call::delete(path))
}

/// `GET …/authorization/roles/{id}/holders`.
#[must_use]
pub fn holders(tenant: &TenantPath, role_id: &str) -> Request<Page<Holder>> {
    Request::of(Call::get(
        tenant.at(&format!("/authorization/roles/{role_id}/holders")),
    ))
}

/// `GET …/authorization/permissions`: the catalogue of built-in
/// permissions.
#[must_use]
pub fn permissions(tenant: &TenantPath) -> Request<Vec<PermissionArea>> {
    Request::of(Call::get(tenant.at("/authorization/permissions")))
}
