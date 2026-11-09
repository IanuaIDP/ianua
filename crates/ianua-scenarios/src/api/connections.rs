//! What a tenant's administrators keep about its connections to outside
//! identity providers beyond setting one up: where an address signs in,
//! switching a connection off and on, its group mapping, sealed
//! assertions, and the links of the tenant's users.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::account::ProviderLinks;
use crate::wire::connections::{
    Connection, DiscoverRealm, EncryptionCertificate, EncryptionKey, GroupMapping, HomeRealm,
};

/// `POST …/federation/discover`: where an address signs in, which anyone
/// may ask.
#[must_use]
pub fn discover(tenant: &TenantPath, address: &DiscoverRealm) -> Request<HomeRealm> {
    Request::of(Call::post(tenant.at("/federation/discover")).json(address))
}

/// `GET …/federation/connections`: the tenant's connections, one page.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Page<Connection>> {
    Request::of(Call::get(tenant.at("/federation/connections")))
}

/// `GET …/federation/connections/{id}`.
#[must_use]
pub fn get(tenant: &TenantPath, id: &str) -> Request<Connection> {
    Request::of(Call::get(
        tenant.at(&format!("/federation/connections/{id}")),
    ))
}

/// `POST …/federation/connections/{id}/activate`.
#[must_use]
pub fn activate(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/federation/connections/{id}/activate")),
    ))
}

/// `POST …/federation/connections/{id}/disable`.
#[must_use]
pub fn disable(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/federation/connections/{id}/disable")),
    ))
}

/// `DELETE …/federation/connections/{id}`.
#[must_use]
pub fn delete(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/federation/connections/{id}")),
    ))
}

/// `PUT …/federation/connections/{id}/group-mapping`.
#[must_use]
pub fn map_groups(tenant: &TenantPath, id: &str, mapping: &GroupMapping) -> Request<()> {
    Request::of(
        Call::put(tenant.at(&format!("/federation/connections/{id}/group-mapping"))).json(mapping),
    )
}

/// `DELETE …/federation/connections/{id}/group-mapping`.
#[must_use]
pub fn stop_mapping_groups(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/federation/connections/{id}/group-mapping")),
    ))
}

/// `PUT …/federation/connections/{id}/encrypted-assertions`: requires
/// assertions sealed to `key`, or to one the platform makes when `key`
/// names none; the certificate for the provider in the answer.
#[must_use]
pub fn require_encrypted_assertions(
    tenant: &TenantPath,
    id: &str,
    key: &EncryptionKey,
) -> Request<EncryptionCertificate> {
    Request::of(
        Call::put(tenant.at(&format!(
            "/federation/connections/{id}/encrypted-assertions"
        )))
        .json(key),
    )
}

/// `DELETE …/federation/connections/{id}/encrypted-assertions`.
#[must_use]
pub fn accept_readable_assertions(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::delete(tenant.at(&format!(
        "/federation/connections/{id}/encrypted-assertions"
    ))))
}

/// `GET …/federation/users/{user_id}/links`: a tenant user's links to
/// identity providers, read by an administrator.
#[must_use]
pub fn user_links(tenant: &TenantPath, user_id: &str) -> Request<ProviderLinks> {
    Request::of(Call::get(
        tenant.at(&format!("/federation/users/{user_id}/links")),
    ))
}

/// `DELETE …/federation/connections/{id}/links/{user_id}`: an
/// administrator removes a tenant user's link.
#[must_use]
pub fn unlink_user(tenant: &TenantPath, id: &str, user_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/federation/connections/{id}/links/{user_id}")),
    ))
}
