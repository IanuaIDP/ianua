//! The apps a Protected apps step may call, on the wire: each route the
//! tenant opened to workflows, as a step names it.

use ianua_domain::domains::routing::route::Route;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::HttpMethod;
use serde::Serialize;
use uuid::Uuid;

use crate::dto::routing::routes::host_names;

/// One route open to workflows.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AppResponse {
    /// The route, which a Protected apps step names in its `route` input.
    pub id: Uuid,
    /// Its name for people.
    pub name: String,
    /// The paths it claims, such as `/orders/*`; a step's `path` must fit
    /// it.
    pub path_pattern: String,
    /// The methods it answers. Empty means all of them.
    #[schema(schema_with = crate::dto::schemas::http_method_list)]
    pub methods: Vec<HttpMethod>,
    /// The domains it answers on. Empty means every domain the tenant has.
    pub hosts: Vec<String>,
}

impl From<Route<ResolvedTenant>> for AppResponse {
    fn from(route: Route<ResolvedTenant>) -> Self {
        Self {
            id: *route.id().as_uuid(),
            name: route.name().as_str().to_owned(),
            path_pattern: route.path_pattern().as_str().to_owned(),
            methods: route.methods().to_vec(),
            hosts: host_names(route.hosts()),
        }
    }
}
