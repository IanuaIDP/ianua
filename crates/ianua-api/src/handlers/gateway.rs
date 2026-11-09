//! Gateway configuration handlers: a tenant's services, pipelines and routes
//! exported as one document, applied back from one, or drafted from an
//! OpenAPI 3 document.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::gateway::GatewayState;

use crate::dto::gateway::openapi::OpenApiImportBody;
use crate::dto::gateway::{ConfigDiffResponse, GatewayConfigBody, ImportConfigBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::document::{Document, Format, Rendered};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/config",
    tag = "Gateway",
    responses(
        (status = 200, description = "The tenant's gateway configuration", body = GatewayConfigBody),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Export the gateway configuration
///
/// Returns the tenant's services, pipelines, routes, stream routes, egress
/// policies and consumers as one document, keyed by name and carrying no
/// ids, so it can be checked into a repository and applied to another
/// tenant. Nothing secret is written down: no client key, no API key or its
/// hash, only what tells a credential apart. Send `Accept:
/// application/yaml` for YAML, which is what a document meant to be read in
/// a pull request usually wants to be. A route whose service or pipeline has
/// gone missing, or a stream route naming a consumer that is gone, is left
/// out: it could not be recreated from the document. Read-only. Requires
/// `Routing(View)` and `Pipeline(View)`.
pub(crate) async fn export_config(
    State(gateway): State<GatewayState>,
    tenant: TenantCaller,
    format: Format,
) -> Result<Rendered<GatewayConfigBody>, ApiError> {
    let config = gateway.export.execute(&tenant.caller, ()).await?;
    Ok(Rendered(format, config.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/config",
    tag = "Gateway",
    request_body = ImportConfigBody,
    responses(
        (status = 200, description = "What the import did, or would do", body = ConfigDiffResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or a create would exceed the plan", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 409, description = "A name or sign-in host is taken, or something to delete is in use", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Apply a gateway configuration
///
/// Accepts JSON or, with `Content-Type: application/yaml`, YAML; answers in
/// whichever format `Accept` names.
///
/// Returns ordered create/update/delete/unchanged results for services, pipelines,
/// routes, consumers, stream routes and egress policies. Defaults to `plan: "dry_run"`
/// and non-deleting `mode: "merge"`; `mode: "replace"` matches the document exactly.
///
/// Refuses the whole document if a route's service or pipeline would be absent.
/// Writes and their audit record commit or roll back together.
/// Records `routing.gateway_config_imported` when it writes; a dry run, or a
/// document that changes nothing, records nothing. Requires `Routing(View)`
/// and `Pipeline(View)`, and the right for each change the plan holds.
pub(crate) async fn import_config(
    State(gateway): State<GatewayState>,
    tenant: TenantCaller,
    format: Format,
    Document(body): Document<ImportConfigBody>,
) -> Result<Rendered<ConfigDiffResponse>, ApiError> {
    let diff = gateway
        .import
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Rendered(format, diff.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/gateway/config/openapi",
    tag = "Gateway",
    request_body = OpenApiImportBody,
    responses(
        (status = 200, description = "The configuration the spec describes", body = GatewayConfigBody),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Convert an OpenAPI 3 document
///
/// Accepts JSON or, with `Content-Type: application/yaml`, YAML, which is how
/// most specs are written.
///
/// Answers with the gateway configuration the spec describes: one service
/// from its server URL, one route per path carrying that path's methods, and
/// the pipeline you name. It writes nothing and reads only the document you
/// supplied: review it, fill in what a spec cannot say, and post it to the
/// configuration endpoint like any other. Requires a session or key of the
/// tenant.
pub(crate) async fn convert_openapi(
    _tenant: TenantCaller,
    format: Format,
    Document(body): Document<OpenApiImportBody>,
) -> Result<Rendered<GatewayConfigBody>, ApiError> {
    Ok(Rendered(format, body.convert()?))
}
