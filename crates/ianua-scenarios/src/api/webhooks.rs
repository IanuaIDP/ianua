//! A tenant's webhooks: subscribing an endpoint, its signing secret, its
//! delivery attempts, sending one again and sending a test event.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::webhooks::{
    NewWebhook, RotateWebhookSecret, Webhook, WebhookChange, WebhookCreated, WebhookDelivery,
    WebhookEventType, WebhookSecret, WebhookTestEvent,
};

/// `GET …/webhooks/event-types`: every event a webhook may be subscribed
/// to.
#[must_use]
pub fn event_types(tenant: &TenantPath) -> Request<Vec<WebhookEventType>> {
    Request::of(Call::get(tenant.at("/webhooks/event-types")))
}

/// `POST …/webhooks`: subscribes an endpoint, its signing secret in the
/// answer, once.
#[must_use]
pub fn create(tenant: &TenantPath, webhook: &NewWebhook) -> Request<WebhookCreated> {
    Request::of(Call::post(tenant.at("/webhooks")).json(webhook))
}

/// `GET …/webhooks`: every subscription of the tenant, one page.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Page<Webhook>> {
    Request::of(Call::get(tenant.at("/webhooks")))
}

/// `GET …/webhooks/{id}`.
#[must_use]
pub fn get(tenant: &TenantPath, id: &str) -> Request<Webhook> {
    Request::of(Call::get(tenant.at(&format!("/webhooks/{id}"))))
}

/// `PATCH …/webhooks/{id}`: changes it; a field left out keeps its value.
#[must_use]
pub fn change(tenant: &TenantPath, id: &str, change: &WebhookChange) -> Request<Webhook> {
    Request::of(Call::patch(tenant.at(&format!("/webhooks/{id}"))).json(change))
}

/// `POST …/webhooks/{id}/pause`.
#[must_use]
pub fn pause(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/webhooks/{id}/pause"))))
}

/// `POST …/webhooks/{id}/resume`.
#[must_use]
pub fn resume(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/webhooks/{id}/resume"))))
}

/// `DELETE …/webhooks/{id}`: a webhook is paused or disabled first.
#[must_use]
pub fn delete(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::delete(tenant.at(&format!("/webhooks/{id}"))))
}

/// `POST …/webhooks/{id}/rotate-secret` with `overlap`: the new secret, in
/// the answer once; the old one keeps signing for `overlap` seconds, or
/// stops at once when `None`.
#[must_use]
pub fn rotate_secret(
    tenant: &TenantPath,
    id: &str,
    overlap: Option<RotateWebhookSecret>,
) -> Request<WebhookSecret> {
    let call = Call::post(tenant.at(&format!("/webhooks/{id}/rotate-secret")));
    Request::of(match overlap {
        Some(overlap) => call.json(&overlap),
        None => call,
    })
}

/// `GET …/webhooks/{id}/deliveries`: every delivery attempt, one page.
#[must_use]
pub fn deliveries(tenant: &TenantPath, id: &str) -> Request<Page<WebhookDelivery>> {
    Request::of(Call::get(tenant.at(&format!("/webhooks/{id}/deliveries"))))
}

/// `POST …/webhooks/{id}/deliveries/{delivery_id}/resend`: sends the
/// message of an earlier attempt again; the new attempt in the answer.
#[must_use]
pub fn resend(tenant: &TenantPath, id: &str, delivery_id: &str) -> Request<WebhookDelivery> {
    Request::of(Call::post(
        tenant.at(&format!("/webhooks/{id}/deliveries/{delivery_id}/resend")),
    ))
}

/// `POST …/webhooks/{id}/test`: sends a sample of an event it lists; how
/// the try ended in the answer.
#[must_use]
pub fn send_test(
    tenant: &TenantPath,
    id: &str,
    event: &WebhookTestEvent,
) -> Request<WebhookDelivery> {
    Request::of(Call::post(tenant.at(&format!("/webhooks/{id}/test"))).json(event))
}
