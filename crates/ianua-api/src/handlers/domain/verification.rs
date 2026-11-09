//! Domain verification handlers: checking a domain's DNS proof on the
//! tenant's request.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_assembly::domain::DomainState;

use crate::dto::domain::verification::VerificationStatusResponse;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::domain::DomainPath;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}/verify",
    tag = "Domains",
    responses(
        (status = 200, description = "Success", body = VerificationStatusResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Trigger DNS verification
///
/// Checks the stored TXT challenge at `_ianua-verify.{domain}` for
/// `SelfManaged` connections, or delegation to our nameservers for `Delegated`.
/// A match sets `Verified` and `verified_at`, requests a certificate and
/// records `tenant.domain_verified`. Returns the resulting status.
/// Missing proof changes and records nothing: DNS may still be cached,
/// and background checks retry. Only health checks can move a verified
/// domain to `Failed`. Requires `Domains(Update)`; missing domains return `404`.
pub(crate) async fn verify_domain(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
) -> Result<Json<VerificationStatusResponse>, ApiError> {
    let status = domains
        .verify
        .execute(&tenant.caller, &tenant.auditor, path.domain())
        .await?;
    Ok(Json(VerificationStatusResponse::from(status)))
}
