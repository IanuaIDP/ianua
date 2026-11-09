//! Handlers for the record sets inside a zone delegated to us.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::domain::DomainState;

use crate::dto::domain::dns_records::{
    DnsRecordSetResponse, RemoveDnsRecordBody, SetDnsRecordBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::domain::DomainPath;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}/dns",
    tag = "Domains",
    responses(
        (status = 200, description = "Success", body = Vec<DnsRecordSetResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Domain is not delegated", body = ErrorBody)
    )
)]
/// List a delegated domain's DNS records
///
/// Returns every record set in the zone, ordered by name and then type. A
/// set is one name and one type with all its values, which is what DNS
/// resolves and what a resolver caches, so it is the unit both read and
/// written here.
///
/// Sets carrying `is_managed_by_ianua` are ours: the address routing the
/// hostname to the proxy, and the `_acme-challenge` names a certificate is
/// issued through. They are listed because hiding records that exist would
/// make the zone look wrong, but writing or removing them is refused.
///
/// Not paginated: a zone is bounded by the plan's record-set limit and is
/// read whole. Returns `409` if the domain is tenant-managed, its records
/// living at the tenant's own provider. Read-only.
///
/// Requires `Domains(View)`.
pub(crate) async fn list_dns_records(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
) -> Result<Json<Vec<DnsRecordSetResponse>>, ApiError> {
    let sets = domains
        .dns_records
        .list
        .execute(&tenant.caller, path.domain())
        .await?;
    Ok(Json(
        sets.into_iter().map(DnsRecordSetResponse::from).collect(),
    ))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}/dns",
    tag = "Domains",
    request_body = SetDnsRecordBody,
    responses(
        (status = 204, description = "Record set written"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Domain is not delegated", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Write a DNS record set
///
/// Replaces every answer the zone gives for one name and type. `PUT`
/// because it is idempotent and total: a set sent with one value leaves
/// exactly one, whatever was there before.
///
/// Values are spelled as a zone file spells them: `203.0.113.10` for `A`,
/// `10 mail.acme.com` for `MX`, `10 5 443 sip.acme.com` for `SRV`,
/// `0 issue "letsencrypt.org"` for `CAA`. A `CNAME` takes exactly one
/// value; every other type may take several.
///
/// **Refused with `422`:** a name outside the zone; a `CNAME` at the zone
/// apex; a `CNAME` beside any other type on the same name, or any type
/// beside an existing `CNAME`; the address on the delegated hostname
/// itself, which routes traffic to the proxy; and any `_acme-challenge`
/// name, which is written during certificate issuance. A new set beyond
/// the plan's record-set limit is `403`, though a set that already exists
/// may always be corrected.
///
/// Returns `409` if the domain is tenant-managed. Records
/// `tenant.dns_record_set_changed`, carrying both the new values and the
/// ones replaced.
///
/// Requires `Domains(Update)`.
pub(crate) async fn set_dns_record(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
    Json(body): Json<SetDnsRecordBody>,
) -> Result<NoContent, ApiError> {
    domains
        .dns_records
        .set
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.domain())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}/dns",
    tag = "Domains",
    request_body = RemoveDnsRecordBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Domain is not delegated", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Remove a DNS record set
///
/// Stops the zone answering for one name and type. The set is named in the
/// body rather than the path, because a record name contains dots and may
/// be the zone apex, neither of which survives a path segment cleanly.
///
/// Removing a set that is not there returns `204` and records nothing: the
/// caller wanted the zone to stop answering, and it does not.
///
/// **Refused with `422`:** a name outside the zone; the address on the
/// delegated hostname; and any `_acme-challenge` name. Returns `409` if the
/// domain is tenant-managed. Records `tenant.dns_record_set_removed`,
/// carrying what the set used to answer.
///
/// Requires `Domains(Delete)`.
pub(crate) async fn remove_dns_record(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
    Json(body): Json<RemoveDnsRecordBody>,
) -> Result<NoContent, ApiError> {
    domains
        .dns_records
        .remove
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.domain())?,
        )
        .await?;
    Ok(NoContent)
}
