//! The audit trail: an organization's log across its tenants, one
//! tenant's log and its exports, the tenant's check of its chain, and the
//! whole platform's log an operator reads.

use super::{OrgPath, Request, TenantPath, with_query};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::audit::{AuditEntry, AuditExport, ChainCheck, ExportAccepted, ExportAsked};

/// The most records one read asks for.
const PAGE: &str = "100";

/// `GET …/audit-log` of an organization: the records whose type starts
/// with `event_type`, newest first.
#[must_use]
pub fn organization_log(org: &OrgPath, event_type: &str) -> Request<Page<AuditEntry>> {
    let pairs = [("event_type", event_type), ("limit", PAGE)];
    Request::of(Call::get(with_query(&org.at("/audit-log"), &pairs)))
}

/// `GET …/tenants/{tenant}/audit-log`: the tenant's records whose type
/// starts with `event_type`, newest first.
#[must_use]
pub fn tenant_log(tenant: &TenantPath, event_type: &str) -> Request<Page<AuditEntry>> {
    let pairs = [("event_type", event_type), ("limit", PAGE)];
    Request::of(Call::get(with_query(&tenant.at("/audit-log"), &pairs)))
}

/// `GET …/tenants/{tenant}/audit-log?{filters}`: the tenant's records the
/// filters and page cursor `filters` name, such as `target`, `since`,
/// `after` and `limit`.
#[must_use]
pub fn tenant_log_where(
    tenant: &TenantPath,
    filters: &[(&str, &str)],
) -> Request<Page<AuditEntry>> {
    Request::of(Call::get(with_query(&tenant.at("/audit-log"), filters)))
}

/// `GET /api/v1/audit-log?{filters}`: the whole platform's records,
/// platform, organization and tenant alike, read with an operator's own
/// key, filtered by `filters` such as `event_type`, `actor` and
/// `tenant_id`, newest first.
#[must_use]
pub fn platform_log_where(filters: &[(&str, &str)]) -> Request<Page<AuditEntry>> {
    let mut pairs = filters.to_vec();
    pairs.push(("limit", PAGE));
    Request::of(Call::get(with_query("/api/v1/audit-log", &pairs)))
}

/// `POST …/tenants/{tenant}/audit-log/exports`.
#[must_use]
pub fn request_tenant_export(tenant: &TenantPath, asked: &ExportAsked) -> Request<ExportAccepted> {
    Request::of(Call::post(tenant.at("/audit-log/exports")).json(asked))
}

/// `GET …/tenants/{tenant}/audit-log/exports/{id}`: where the export
/// stands, with a fresh download link once it is ready.
#[must_use]
pub fn tenant_export(tenant: &TenantPath, export_id: &str) -> Request<AuditExport> {
    Request::of(Call::get(
        tenant.at(&format!("/audit-log/exports/{export_id}")),
    ))
}

/// `GET …/tenants/{tenant}/audit/verify`.
#[must_use]
pub fn verify_chain(tenant: &TenantPath) -> Request<ChainCheck> {
    Request::of(Call::get(tenant.at("/audit/verify")))
}

/// `GET …/audit-log?{filters}` of an organization: its own records and
/// every tenant's, narrowed and paged by `filters`, such as `event_type`,
/// `tenant_id`, `actor`, `after` and `limit`, newest first.
#[must_use]
pub fn organization_log_where(
    org: &OrgPath,
    filters: &[(&str, &str)],
) -> Request<Page<AuditEntry>> {
    Request::of(Call::get(with_query(&org.at("/audit-log"), filters)))
}

/// `POST …/audit-log/exports` of an organization.
#[must_use]
pub fn request_organization_export(org: &OrgPath, asked: &ExportAsked) -> Request<ExportAccepted> {
    Request::of(Call::post(org.at("/audit-log/exports")).json(asked))
}

/// `GET …/audit-log/exports/{id}` of an organization: where the export
/// stands, with a fresh download link once it is ready.
#[must_use]
pub fn organization_export(org: &OrgPath, export_id: &str) -> Request<AuditExport> {
    Request::of(Call::get(
        org.at(&format!("/audit-log/exports/{export_id}")),
    ))
}
