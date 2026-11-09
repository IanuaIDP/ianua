//! The SCIM 2.0 provisioning service, under the base URL an administrator
//! gives their identity provider:
//! `/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}`.

use std::time::Duration;

use axum::Router;
use utoipa::OpenApi;

use crate::dto::scim::{
    ScimEmail, ScimEnterpriseUser, ScimGroupBody, ScimMemberRef, ScimName, ScimPatchBody,
    ScimPatchOperation, ScimUserBody,
};
use crate::handlers::scim::{discovery, groups, users};
use crate::method::{any, get, shared};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The SCIM endpoints, limited per client address.
///
/// A directory signs in with its bearer token on every request, so the
/// limit is per address: one that guesses tokens or tenant names is slowed
/// before any is checked.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let limiter = per_address(
        state,
        state.http.rate.scim_per_minute,
        Duration::from_secs(60),
    );
    endpoints().layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// Every SCIM endpoint, under the base URL.
fn endpoints() -> Router<ApiState> {
    let base = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}";
    Router::new()
        .route(
            &format!("{base}/ServiceProviderConfig"),
            get(discovery::service_provider_config),
        )
        .route(
            &format!("{base}/ResourceTypes"),
            get(discovery::resource_types),
        )
        .route(&format!("{base}/Schemas"), get(discovery::schemas))
        .merge(provisioning_routes(base))
}

/// Registers SCIM user and group provisioning below the discovery endpoints.
fn provisioning_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/Users"),
            get(users::list_users).post(shared(users::create_user)),
        )
        .route(
            &format!("{base}/Users/{{id}}"),
            get(users::get_user)
                .put(shared(users::replace_user))
                .patch(shared(users::patch_user))
                .delete(shared(users::delete_user)),
        )
        .route(&format!("{base}/Me"), any(users::me))
        .route(
            &format!("{base}/Groups"),
            get(groups::list_groups).post(shared(groups::create_group)),
        )
        .route(
            &format!("{base}/Groups/{{id}}"),
            get(groups::get_group)
                .put(shared(groups::replace_group))
                .patch(shared(groups::patch_group))
                .delete(shared(groups::delete_group)),
        )
}

/// The SCIM part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        discovery::service_provider_config,
        discovery::resource_types,
        discovery::schemas,
        users::list_users,
        users::get_user,
        users::create_user,
        users::replace_user,
        users::patch_user,
        users::delete_user,
        users::me,
        groups::list_groups,
        groups::get_group,
        groups::create_group,
        groups::replace_group,
        groups::patch_group,
        groups::delete_group,
    ),
    components(schemas(
        ScimUserBody,
        ScimName,
        ScimEmail,
        ScimEnterpriseUser,
        ScimGroupBody,
        ScimMemberRef,
        ScimPatchBody,
        ScimPatchOperation,
    ))
)]
pub(crate) struct Document;
