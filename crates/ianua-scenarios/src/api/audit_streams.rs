//! The streams of a tenant's audit records to outside collectors.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::audit_streams::{AuditStream, AuditStreamCreated, AuditStreamSetup};

/// `GET …/audit-streams`: the tenant's streams, never a credential.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Vec<AuditStream>> {
    Request::of(Call::get(tenant.at("/audit-streams")))
}

/// `POST …/audit-streams`: adds a stream, proved by the password typed
/// again.
#[must_use]
pub fn create(tenant: &TenantPath, setup: &AuditStreamSetup) -> Request<AuditStreamCreated> {
    Request::of(Call::post(tenant.at("/audit-streams")).json(setup))
}

/// `PUT …/audit-streams/{id}`: changes the whole of a stream.
#[must_use]
pub fn reconfigure(tenant: &TenantPath, id: &str, setup: &AuditStreamSetup) -> Request<()> {
    Request::of(Call::put(tenant.at(&format!("/audit-streams/{id}"))).json(setup))
}

/// `POST …/audit-streams/{id}/pause`.
#[must_use]
pub fn pause(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/audit-streams/{id}/pause"))))
}

/// `POST …/audit-streams/{id}/resume`.
#[must_use]
pub fn resume(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/audit-streams/{id}/resume")),
    ))
}

/// `DELETE …/audit-streams/{id}`.
#[must_use]
pub fn remove(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::delete(tenant.at(&format!("/audit-streams/{id}"))))
}
