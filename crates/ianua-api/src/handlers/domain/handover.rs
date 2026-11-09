//! Domain handover handlers: the giving tenant offers a domain, the
//! receiving tenant takes it.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_assembly::domain::DomainState;

use crate::dto::domain::handover::{AcceptHandoverBody, HandoverOfferResponse, OfferHandoverBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::domain::DomainPath;
use crate::response::NoContent;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domains/{id}/handover",
    tag = "Domains",
    request_body = OfferHandoverBody,
    responses(
        (status = 200, description = "Offer made", body = HandoverOfferResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Offer a domain to another tenant
///
/// The first of two steps that move a domain registration to a different
/// tenant **of the same organization**: this tenant offers it, and the
/// target tenant takes it with `POST …/domain-handovers/accept`. Nothing
/// moves until then, and nothing is recorded: the domain stays this
/// tenant's. A new offer of the same domain replaces an earlier one.
/// Answers when the offer runs out (`expires_at`).
///
/// Returns `404` if the domain or either tenant does not exist; `409` if
/// the target is this tenant, belongs to a different organization, or the
/// domain is this tenant's primary domain; `422` if either tenant is
/// closed.
///
/// Requires `Domains(Update)` on the tenant the domain is leaving.
pub(crate) async fn offer_domain_handover(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Path(path): Path<DomainPath>,
    Json(body): Json<OfferHandoverBody>,
) -> Result<Json<HandoverOfferResponse>, ApiError> {
    let expires_at = domains
        .handover
        .offer
        .execute(&tenant.caller, &tenant.auditor, body.request(path.domain()))
        .await?;
    Ok(Json(HandoverOfferResponse { expires_at }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/domain-handovers/accept",
    tag = "Domains",
    request_body = AcceptHandoverBody,
    responses(
        (status = 204, description = "Domain taken over"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Take over a domain another tenant offered
///
/// The second step of a handover: this tenant takes the `domain` that
/// `source_tenant_id` offered it, keeping its verification and certificate.
/// The zone of a delegated domain moves with it, and the name keeps
/// answering across the move. Records `tenant.domain_transferred`.
///
/// Returns `404` if either tenant, the offer or the domain does not exist;
/// `403` if the offer was made to another tenant or the plan's domain limit
/// is reached; `409` if the offer was accepted already or ran out, the
/// tenants belong to different organizations, or the domain became the
/// giving tenant's primary domain; `422` if either tenant is closed.
///
/// Requires `Domains(Update)` on the tenant taking the domain.
pub(crate) async fn accept_domain_handover(
    State(domains): State<DomainState>,
    tenant: TenantCaller,
    Json(body): Json<AcceptHandoverBody>,
) -> Result<NoContent, ApiError> {
    domains
        .handover
        .accept
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}
