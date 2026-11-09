//! A tenant's custom user fields: declaring, changing, withdrawing and
//! discarding them, and the values each person holds.

use super::{Request, TenantPath, with_query};
use crate::net::Call;
use crate::wire::attributes::{
    AttributeDeleted, AttributeKindEntry, AttributeStatus, AttributeValue, AttributeValues,
    ChangeAttribute, DeclareAttribute, DeclaredAttribute,
};

/// The path of a person's value under `namespace` and `key`.
fn value_path(tenant: &TenantPath, user: &str, namespace: &str, key: &str) -> String {
    tenant.at(&format!("/users/{user}/attributes/{namespace}/{key}"))
}

/// The path of the field declared under `namespace` and `key`.
fn declared_path(tenant: &TenantPath, namespace: &str, key: &str) -> String {
    tenant.at(&format!("/user-attributes/{namespace}/{key}"))
}

/// `GET …/user-attributes/kinds`: what a field may be declared as.
#[must_use]
pub fn kinds(tenant: &TenantPath) -> Request<Vec<AttributeKindEntry>> {
    Request::of(Call::get(tenant.at("/user-attributes/kinds")))
}

/// `GET …/user-attributes`, withdrawn fields too when `archived` is
/// `"true"`.
#[must_use]
pub fn list(tenant: &TenantPath, archived: &str) -> Request<Vec<DeclaredAttribute>> {
    let pairs = [("include_archived", archived)];
    Request::of(Call::get(with_query(
        &tenant.at("/user-attributes"),
        &pairs,
    )))
}

/// `POST …/user-attributes`: declares a field.
#[must_use]
pub fn declare(tenant: &TenantPath, field: &DeclareAttribute) -> Request<DeclaredAttribute> {
    Request::of(Call::post(tenant.at("/user-attributes")).json(field))
}

/// `PATCH …/user-attributes/{namespace}/{key}`: changes a declared field.
#[must_use]
pub fn change(
    tenant: &TenantPath,
    namespace: &str,
    key: &str,
    change: &ChangeAttribute,
) -> Request<DeclaredAttribute> {
    Request::of(Call::patch(declared_path(tenant, namespace, key)).json(change))
}

/// `PUT …/user-attributes/{namespace}/{key}/status`: withdraws a field or
/// brings it back.
#[must_use]
pub fn set_status(
    tenant: &TenantPath,
    namespace: &str,
    key: &str,
    status: &AttributeStatus,
) -> Request<DeclaredAttribute> {
    let path = format!("{}/status", declared_path(tenant, namespace, key));
    Request::of(Call::put(path).json(status))
}

/// `DELETE …/user-attributes/{namespace}/{key}`: discards a withdrawn
/// field and its values.
#[must_use]
pub fn remove(tenant: &TenantPath, namespace: &str, key: &str) -> Request<AttributeDeleted> {
    Request::of(Call::delete(declared_path(tenant, namespace, key)))
}

/// `GET …/users/{id}/attributes`: a person's values the caller may read.
#[must_use]
pub fn values(tenant: &TenantPath, user: &str) -> Request<AttributeValues> {
    Request::of(Call::get(tenant.at(&format!("/users/{user}/attributes"))))
}

/// One person's value under one declared field.
#[derive(Debug, Clone, Copy)]
pub struct HeldValue<'a> {
    /// The id of the person it is written for.
    pub user: &'a str,
    /// `user` when the person keeps it, `app` when only staff do.
    pub namespace: &'a str,
    /// The field's internal name.
    pub key: &'a str,
}

/// `PUT …/users/{id}/attributes/{namespace}/{key}`: sets or clears one
/// value.
#[must_use]
pub fn set_value(tenant: &TenantPath, held: HeldValue<'_>, value: &AttributeValue) -> Request<()> {
    let path = value_path(tenant, held.user, held.namespace, held.key);
    Request::of(Call::put(path).json(value))
}

/// `DELETE …/users/{id}/attributes`: clears every value a person holds.
#[must_use]
pub fn clear_values(tenant: &TenantPath, user: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/users/{user}/attributes")),
    ))
}
