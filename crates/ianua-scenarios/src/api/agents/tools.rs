//! The tools runs may call: registering one over its route.

use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::Created;
use crate::wire::agents::tools::{RegisterTool, Tool};

/// `POST …/tools`.
#[must_use]
pub fn register(tenant: &TenantPath, tool: &RegisterTool) -> Request<Created> {
    Request::of(Call::post(tenant.at("/tools")).json(tool))
}

/// `GET …/tools`.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Vec<Tool>> {
    Request::of(Call::get(tenant.at("/tools")))
}
