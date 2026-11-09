//! The systems a Protected data step may reach, on the wire: each stream
//! route the tenant opened to workflows, as a step names it. The login kept
//! for each is never shown.

use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::isolation::scope::ResolvedTenant;
use serde::Serialize;
use uuid::Uuid;

/// One stream route open to workflows.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DataResponse {
    /// The stream route, which a Protected data step names in its `route`
    /// input.
    pub id: Uuid,
    /// Its name for people.
    pub name: String,
}

impl From<StreamRoute<ResolvedTenant>> for DataResponse {
    fn from(route: StreamRoute<ResolvedTenant>) -> Self {
        Self {
            id: *route.id().as_uuid(),
            name: route.name().as_str().to_owned(),
        }
    }
}
