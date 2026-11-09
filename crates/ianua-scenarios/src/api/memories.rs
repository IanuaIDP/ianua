//! Memories: making one, listing them, deleting one after typing its name,
//! bringing one back, and reading its texts.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::memories::{DeleteMemory, Memory, MemoryEntryPage, NewMemory};

/// `POST …/memories`: makes a memory.
#[must_use]
pub fn create(tenant: &TenantPath, memory: &NewMemory) -> Request<Memory> {
    Request::of(Call::post(tenant.at("/memories")).json(memory))
}

/// `GET …/memories`: the tenant's memories.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Vec<Memory>> {
    Request::of(Call::get(tenant.at("/memories")))
}

/// `POST …/memories/{id}/delete`: sets it to be deleted.
#[must_use]
pub fn delete(tenant: &TenantPath, memory_id: &str, typed: &DeleteMemory) -> Request<Memory> {
    Request::of(Call::post(tenant.at(&format!("/memories/{memory_id}/delete"))).json(typed))
}

/// `POST …/memories/{id}/restore`: brings it back.
#[must_use]
pub fn restore(tenant: &TenantPath, memory_id: &str) -> Request<Memory> {
    Request::of(Call::post(
        tenant.at(&format!("/memories/{memory_id}/restore")),
    ))
}

/// `GET …/memories/{id}/entries`: the first page of its texts.
#[must_use]
pub fn entries(tenant: &TenantPath, memory_id: &str) -> Request<MemoryEntryPage> {
    Request::of(Call::get(
        tenant.at(&format!("/memories/{memory_id}/entries")),
    ))
}
