//! SCIM discovery handlers: what this service supports, for a provider
//! setting up a connection. The same for every tenant: they describe the
//! code and the deployment's limits, not the tenant.

use axum::extract::State;
use ianua_assembly::scim::ScimState;
use serde_json::Value;

use crate::dto::scim::discovery;
use crate::response::scim::ScimJson;

#[utoipa::path(
    get,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/ServiceProviderConfig",
    tag = "SCIM",
    responses(
        (status = 200, description = "The SCIM ServiceProviderConfig", content_type = "application/scim+json")
    )
)]
/// SCIM service provider configuration
///
/// What this service supports: patch, filtering, sorting and ETags; no
/// bulk or password changes; and the tenant's bearer token as the one
/// authentication scheme. The extension
/// `urn:ianua:params:scim:schemas:extension:limits:2.0:ServiceProviderConfig`
/// gives `maxMembersPerOperation`, the most members one group write names
/// across all its operations; a write naming more is answered `400` with
/// `scimType` `tooMany`. Public. Records nothing.
pub(crate) async fn service_provider_config(State(scim): State<ScimState>) -> ScimJson<Value> {
    ScimJson::ok(discovery::service_provider_config(scim.member_cap.most()))
}

#[utoipa::path(
    get,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/ResourceTypes",
    tag = "SCIM",
    responses(
        (status = 200, description = "A SCIM ListResponse of ResourceType resources", content_type = "application/scim+json")
    )
)]
/// SCIM resource types
///
/// The resource types this service provisions: `User`, with the enterprise
/// extension, and `Group`. Public. Records nothing.
pub(crate) async fn resource_types() -> ScimJson<Value> {
    ScimJson::ok(discovery::resource_types())
}

#[utoipa::path(
    get,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Schemas",
    tag = "SCIM",
    responses(
        (status = 200, description = "A SCIM ListResponse of Schema resources", content_type = "application/scim+json")
    )
)]
/// SCIM schemas
///
/// The attributes this service reads and returns for users, their
/// enterprise extension, and groups.
/// Public. Records nothing.
pub(crate) async fn schemas() -> ScimJson<Value> {
    ScimJson::ok(discovery::schemas())
}
