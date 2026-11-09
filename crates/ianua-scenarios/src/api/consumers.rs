//! A tenant's consumers: making one with a key shown once, reading,
//! renaming, limiting and clearing it, rotating its key, switching it off
//! and on, and deleting it.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::consumers::{
    ClearanceChange, Consumer, ConsumerMade, ConsumerName, DescriptionChange, ExpiryChange,
    NewConsumer, QuotaChange, Rotated, Rotation,
};

/// `POST …/consumers`.
#[must_use]
pub fn create(tenant: &TenantPath, consumer: &NewConsumer) -> Request<ConsumerMade> {
    Request::of(Call::post(tenant.at("/consumers")).json(consumer))
}

/// `GET …/consumers`.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Page<Consumer>> {
    Request::of(Call::get(tenant.at("/consumers")))
}

/// `GET …/consumers/{id}`.
#[must_use]
pub fn get(tenant: &TenantPath, consumer_id: &str) -> Request<Consumer> {
    Request::of(Call::get(tenant.at(&format!("/consumers/{consumer_id}"))))
}

/// `PATCH …/consumers/{id}`: renames it.
#[must_use]
pub fn rename(tenant: &TenantPath, consumer_id: &str, name: &ConsumerName) -> Request<()> {
    let path = tenant.at(&format!("/consumers/{consumer_id}"));
    Request::of(Call::patch(path).json(name))
}

/// `PUT …/consumers/{id}/quota`.
#[must_use]
pub fn change_quota(
    tenant: &TenantPath,
    consumer_id: &str,
    change: &QuotaChange,
) -> Request<Consumer> {
    let path = tenant.at(&format!("/consumers/{consumer_id}/quota"));
    Request::of(Call::put(path).json(change))
}

/// `PUT …/consumers/{id}/clearance`.
#[must_use]
pub fn change_clearance(
    tenant: &TenantPath,
    consumer_id: &str,
    change: &ClearanceChange,
) -> Request<Consumer> {
    let path = tenant.at(&format!("/consumers/{consumer_id}/clearance"));
    Request::of(Call::put(path).json(change))
}

/// `PUT …/consumers/{id}/description`.
#[must_use]
pub fn describe(tenant: &TenantPath, consumer_id: &str, change: &DescriptionChange) -> Request<()> {
    let path = tenant.at(&format!("/consumers/{consumer_id}/description"));
    Request::of(Call::put(path).json(change))
}

/// `PUT …/consumers/{id}/expiry`.
#[must_use]
pub fn change_expiry(
    tenant: &TenantPath,
    consumer_id: &str,
    change: &ExpiryChange,
) -> Request<Consumer> {
    let path = tenant.at(&format!("/consumers/{consumer_id}/expiry"));
    Request::of(Call::put(path).json(change))
}

/// `POST …/consumers/{id}/rotate`: a new key, shown once.
#[must_use]
pub fn rotate(tenant: &TenantPath, consumer_id: &str, rotation: &Rotation) -> Request<Rotated> {
    let path = tenant.at(&format!("/consumers/{consumer_id}/rotate"));
    Request::of(Call::post(path).json(rotation))
}

/// `POST …/consumers/{id}/end-overlap`: the replaced key stops now.
#[must_use]
pub fn end_overlap(tenant: &TenantPath, consumer_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/consumers/{consumer_id}/end-overlap"));
    Request::of(Call::post(path))
}

/// `POST …/consumers/{id}/disable`.
#[must_use]
pub fn disable(tenant: &TenantPath, consumer_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/consumers/{consumer_id}/disable"));
    Request::of(Call::post(path))
}

/// `POST …/consumers/{id}/enable`.
#[must_use]
pub fn enable(tenant: &TenantPath, consumer_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/consumers/{consumer_id}/enable"));
    Request::of(Call::post(path))
}

/// `DELETE …/consumers/{id}`: only a disabled one.
#[must_use]
pub fn delete(tenant: &TenantPath, consumer_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/consumers/{consumer_id}")),
    ))
}
