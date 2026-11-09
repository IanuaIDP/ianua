//! A tenant's own domains.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::domains::{Domain, NewDomain, ServedCertificate, UploadCertificate, Verification};

/// `GET …/domains`.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Page<Domain>> {
    Request::of(Call::get(tenant.at("/domains")))
}

/// `POST …/domains`.
#[must_use]
pub fn add(tenant: &TenantPath, domain: &NewDomain) -> Request<Domain> {
    Request::of(Call::post(tenant.at("/domains")).json(domain))
}

/// `GET …/domains/{id}`.
#[must_use]
pub fn get(tenant: &TenantPath, domain_id: &str) -> Request<Domain> {
    Request::of(Call::get(tenant.at(&format!("/domains/{domain_id}"))))
}

/// `DELETE …/domains/{id}`.
#[must_use]
pub fn remove(tenant: &TenantPath, domain_id: &str) -> Request<()> {
    Request::of(Call::delete(tenant.at(&format!("/domains/{domain_id}"))))
}

/// `POST …/domains/{id}/verify`.
#[must_use]
pub fn verify(tenant: &TenantPath, domain_id: &str) -> Request<Verification> {
    Request::of(Call::post(
        tenant.at(&format!("/domains/{domain_id}/verify")),
    ))
}

/// `PUT …/domains/{id}/certificate`.
#[must_use]
pub fn upload_certificate(
    tenant: &TenantPath,
    domain_id: &str,
    certificate: &UploadCertificate,
) -> Request<ServedCertificate> {
    let path = tenant.at(&format!("/domains/{domain_id}/certificate"));
    Request::of(Call::put(path).json(certificate))
}
