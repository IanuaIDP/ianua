//! The topics the relay publishes to, made by a person who manages
//! messaging.

use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::Created;
use crate::wire::agents::messaging::NewTopic;

/// `POST …/messaging/topics`.
#[must_use]
pub fn create_topic(tenant: &TenantPath, topic: &NewTopic) -> Request<Created> {
    Request::of(Call::post(tenant.at("/messaging/topics")).json(topic))
}
