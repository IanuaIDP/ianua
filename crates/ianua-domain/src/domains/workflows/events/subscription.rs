//! The records of a workflow's registration at an integration's service:
//! made, lapsed and removed. None carries the secret the service signs
//! with.

use time::OffsetDateTime;

use crate::domains::workflows::events::VersionRef;
use crate::domains::workflows::integration::IntegrationKey;
use crate::domains::workflows::integration::events::ServiceEventKey;
use crate::domains::workflows::triggers::subscription::LapseReason;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::ServiceSubscriptionId;
use crate::types::event_type::WorkflowsEvent;

/// Which registration an event is about.
#[derive(Debug, Clone)]
pub(crate) struct SubscriptionRef {
    /// The registration.
    pub(crate) subscription_id: ServiceSubscriptionId,
    /// The version it starts.
    pub(crate) version: VersionRef,
    /// The integration whose service sends the event.
    pub(crate) integration: IntegrationKey,
    /// The service-side event kind that starts the referenced workflow revision.
    pub(crate) event: ServiceEventKey,
}

impl SubscriptionRef {
    fn payload(&self) -> EventData {
        self.version
            .payload()
            .field("subscription_id", self.subscription_id.to_string())
            .field("integration", self.integration.as_str().to_owned())
            .field("event", self.event.as_str().to_owned())
    }
}

/// A workflow was registered at an integration's service, which now sends
/// it the events it starts on.
#[derive(Debug)]
pub(crate) struct ServiceSubscriptionRegistered {
    /// The registration.
    pub(crate) subscription: SubscriptionRef,
    /// When the service took it.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ServiceSubscriptionRegistered => WorkflowsEvent::SubscriptionRegistered,
    fn payload(&self) -> EventData {
        self.subscription.payload()
    }
}

/// A workflow's registration lapsed, or could not be made or renewed. The
/// service's events no longer start it.
#[derive(Debug)]
pub(crate) struct ServiceSubscriptionLapsed {
    /// The registration.
    pub(crate) subscription: SubscriptionRef,
    /// Why, in the platform's own words.
    pub(crate) reason: LapseReason,
    /// When it lapsed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ServiceSubscriptionLapsed => WorkflowsEvent::SubscriptionLapsed,
    fn payload(&self) -> EventData {
        self.subscription
            .payload()
            .field("reason", self.reason.as_str().to_owned())
    }
}

/// A workflow's registration was removed, as its version left service.
#[derive(Debug)]
pub(crate) struct ServiceSubscriptionRemoved {
    /// The registration.
    pub(crate) subscription: SubscriptionRef,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ServiceSubscriptionRemoved => WorkflowsEvent::SubscriptionRemoved,
    fn payload(&self) -> EventData {
        self.subscription.payload()
    }
}
