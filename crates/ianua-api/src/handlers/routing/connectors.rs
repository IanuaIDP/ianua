//! Connector handlers: the agents inside a tenant's private network that
//! the gateway reaches upstreams with no public address through, their
//! enrollment, and the renewal of the certificates they hold their links
//! with.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::routing::RoutingState;

use crate::dto::routing::connectors::{
    ChangeConnectorScopeBody, ConnectorCertificateResponse, ConnectorResponse, CreateConnectorBody,
    CreateConnectorResponse, EnrollConnectorBody, RenewConnectorBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::routing::ConnectorPath;
use crate::extractors::public_tenant::PublicTenant;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors",
    tag = "Routing",
    request_body = CreateConnectorBody,
    responses(
        (status = 201, description = "Created, with the one-time enrollment code", body = CreateConnectorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or at the plan's connector limit", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 409, description = "Another connector has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Add a connector
///
/// Adds a private-network connector awaiting enrollment: an agent run
/// inside the tenant's network that the gateway reaches upstreams with no
/// public address through. Its `scope` names the networks and domains it
/// may be asked to dial; nothing else is dialled through it. Answers the
/// one-time `enrollment_code` the agent enrolls with, shown this once and
/// good for an hour; only its hash is kept. Checked against the plan's
/// connector limit. Records `routing.connector_created`. Requires
/// `Routing(Create)`.
pub(crate) async fn create_connector(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Json(body): Json<CreateConnectorBody>,
) -> Result<Created<CreateConnectorResponse>, ApiError> {
    let created = routing
        .create_connector
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(created.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors",
    tag = "Routing",
    responses(
        (status = 200, description = "Success", body = Vec<ConnectorResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List connectors
///
/// Returns this tenant's connectors: each one's scope, whether it is
/// `Active` or `Revoked`, and whether its agent has enrolled. Read-only.
/// Requires `Routing(View)`.
pub(crate) async fn list_connectors(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<ConnectorResponse>>, ApiError> {
    let connectors = routing.list_connectors.execute(&tenant.caller, ()).await?;
    Ok(Json(
        connectors
            .into_iter()
            .map(ConnectorResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors/{id}",
    tag = "Routing",
    responses(
        (status = 200, description = "Success", body = ConnectorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connector", body = ErrorBody)
    )
)]
/// Get a connector
///
/// Returns one connector by `id`. Read-only. Requires `Routing(View)`.
pub(crate) async fn get_connector(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectorPath>,
) -> Result<Json<ConnectorResponse>, ApiError> {
    let connector = routing
        .get_connector
        .execute(&tenant.caller, path.connector())
        .await?;
    Ok(Json(ConnectorResponse::from(connector)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors/{id}/scope",
    tag = "Routing",
    request_body = ChangeConnectorScopeBody,
    responses(
        (status = 204, description = "Saved"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connector", body = ErrorBody),
        (status = 422, description = "Revoked, or a service reached through it falls outside the new scope", body = ErrorBody)
    )
)]
/// Change what a connector may dial
///
/// Replaces the connector's scope. A narrower scope leaving out a service
/// still reached through the connector is refused until the service moves,
/// so no service is cut off without a word. Records
/// `routing.connector_updated`. Requires `Routing(Update)`.
pub(crate) async fn change_connector_scope(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectorPath>,
    Json(body): Json<ChangeConnectorScopeBody>,
) -> Result<NoContent, ApiError> {
    routing
        .change_connector_scope
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.connector()),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors/{id}/revoke",
    tag = "Routing",
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connector", body = ErrorBody),
        (status = 422, description = "Already revoked", body = ErrorBody)
    )
)]
/// Revoke a connector
///
/// Refuses the connector's tunnel for good: the gateway closes it, and
/// every service reached through it is unreachable until moved to another
/// connector. A connector whose certificate may have leaked is replaced,
/// never trusted again.
///
/// **State.** `Active -> Revoked`. Records `routing.connector_revoked`.
/// Requires `Routing(Update)`.
pub(crate) async fn revoke_connector(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectorPath>,
) -> Result<NoContent, ApiError> {
    routing
        .revoke_connector
        .execute(&tenant.caller, &tenant.auditor, path.connector())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors/{id}",
    tag = "Routing",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connector", body = ErrorBody),
        (status = 409, description = "A service is still reached through it", body = ErrorBody),
        (status = 422, description = "Not revoked yet", body = ErrorBody)
    )
)]
/// Delete a connector
///
/// Removes a revoked connector. It is revoked first, so its tunnel is
/// closed before its record goes, and every service reached through it is
/// moved off first. Records `routing.connector_deleted`. Requires
/// `Routing(Delete)`.
pub(crate) async fn delete_connector(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectorPath>,
) -> Result<NoContent, ApiError> {
    routing
        .delete_connector
        .execute(&tenant.caller, &tenant.auditor, path.connector())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors/enroll",
    tag = "Routing",
    request_body = EnrollConnectorBody,
    responses(
        (status = 200, description = "Enrolled, with the connector's first certificate", body = ConnectorCertificateResponse),
        (status = 403, description = "The code is not good", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "The signing request does not read, or its signature does not hold", body = ErrorBody),
        (status = 429, description = "Too many attempts from this address", body = ErrorBody)
    )
)]
/// Enroll a connector's agent (agent only)
///
/// Called by the agent inside the tenant's network, with no session or
/// key: it presents the one-time `code` an administrator was shown, and a
/// PEM signing request `csr` for the key it holds its link with. The
/// request's signature shows the agent holds that key; only the key is
/// taken from it. An unknown, spent, expired or revoked code is `403`
/// alike, and says no more. The code is spent, the key is pinned, and the
/// answer holds a certificate for that key signed by the platform's
/// connector authority, good for a day, with the authority's own
/// certificate to check the gateway's connector listener by. Limited per
/// client address. Records `routing.connector_enrolled`.
pub(crate) async fn enroll_connector(
    State(routing): State<RoutingState>,
    tenant: PublicTenant,
    Json(body): Json<EnrollConnectorBody>,
) -> Result<Json<ConnectorCertificateResponse>, ApiError> {
    let issued = routing
        .enroll_connector
        .execute(&tenant.tenant, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Json(issued.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors/{id}/renew",
    tag = "Routing",
    request_body = RenewConnectorBody,
    responses(
        (status = 200, description = "The connector's next certificate", body = ConnectorCertificateResponse),
        (status = 403, description = "No such connector, revoked, not enrolled, or another key", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "The signing request does not read, or its signature does not hold", body = ErrorBody),
        (status = 429, description = "Too many attempts from this address", body = ErrorBody)
    )
)]
/// Renew a connector's certificate (agent only)
///
/// Called by the agent with no session or key: it sends a new PEM signing
/// request `csr` for the key it enrolled with, which shows it still holds
/// that key. In the certificate's last eight hours, or once it ran out,
/// the answer is a certificate good for a day from now, and
/// `routing.connector_renewed` is recorded. Asked earlier, the answer is a
/// certificate ending when the one held now ends, and nothing is
/// recorded. A connector this tenant does not have, a revoked or
/// unenrolled one, and a request for any other key are `403` alike.
/// Limited per client address.
pub(crate) async fn renew_connector(
    State(routing): State<RoutingState>,
    tenant: PublicTenant,
    Path(path): Path<ConnectorPath>,
    Json(body): Json<RenewConnectorBody>,
) -> Result<Json<ConnectorCertificateResponse>, ApiError> {
    let issued = routing
        .renew_connector
        .execute(
            &tenant.tenant,
            &tenant.auditor,
            body.into_request(path.connector())?,
        )
        .await?;
    Ok(Json(issued.into()))
}
