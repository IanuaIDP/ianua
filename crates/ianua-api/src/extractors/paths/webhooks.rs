//! The webhook subscription, and the delivery attempt of it, a request
//! names.

use ianua_domain::types::{WebhookDeliveryId, WebhookSubscriptionId};
use serde::Deserialize;
use uuid::Uuid;

/// `.../webhooks/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct WebhookPath {
    id: Uuid,
}

impl WebhookPath {
    /// The subscription named.
    #[must_use]
    pub(crate) fn subscription(&self) -> WebhookSubscriptionId {
        WebhookSubscriptionId::from_uuid(self.id)
    }
}

/// `.../webhooks/{id}/deliveries/{delivery_id}/...`.
#[derive(Deserialize)]
pub(crate) struct WebhookDeliveryPath {
    id: Uuid,
    delivery_id: Uuid,
}

impl WebhookDeliveryPath {
    /// The subscription named.
    #[must_use]
    pub(crate) fn subscription(&self) -> WebhookSubscriptionId {
        WebhookSubscriptionId::from_uuid(self.id)
    }

    /// The delivery attempt named.
    #[must_use]
    pub(crate) fn delivery(&self) -> WebhookDeliveryId {
        WebhookDeliveryId::from_uuid(self.delivery_id)
    }
}
