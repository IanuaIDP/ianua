//! The events a webhook may be subscribed to, with what each means.
//!
//! A person choosing what a webhook receives is shown only the events they
//! may see themselves, so the list never names an event they could not
//! subscribe to.

use crate::message;
use crate::shared::errors::DomainError;
use crate::types::event_type::WebhooksEvent;
use crate::types::{EventType, EventVisibility};

/// The one event a webhook never receives: the record of its own delivery.
///
/// Each delivery would raise this event, which would be delivered again,
/// without end.
pub(crate) const DELIVERY: EventType = EventType::Webhooks(WebhooksEvent::DeliveryAttempted);

/// One event a webhook may be subscribed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogEntry {
    event_type: EventType,
}

impl CatalogEntry {
    /// The typed event accepted by a subscription using this catalogue entry.
    #[must_use]
    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    /// The dotted name a subscription lists it under.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.event_type.as_str()
    }

    /// What the event means.
    #[must_use]
    pub fn description(&self) -> &'static str {
        self.event_type.description()
    }
}

/// Every event someone who sees what `seen_by` sees may subscribe a webhook
/// to, in the order the contexts list them.
#[must_use]
pub fn subscribable_events(seen_by: &impl EventVisibility) -> Vec<CatalogEntry> {
    EventType::all()
        .filter(|event_type| may_subscribe(event_type, seen_by))
        .map(|event_type| CatalogEntry { event_type })
        .collect()
}

/// Whether a webhook made by someone who sees what `seen_by` sees may list
/// `event_type`.
fn may_subscribe(event_type: &EventType, seen_by: &impl EventVisibility) -> bool {
    *event_type != DELIVERY && seen_by.may_see(event_type)
}

/// The event types a subscription receives: the ones asked for, each one
/// the person may see, or every one they may see when none was named.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the list names the webhook delivery
///   event, or the person may see no event at all.
/// - [`DomainError::Forbidden`] when the list names an event the person may
///   not see.
pub(crate) fn subscribed(
    asked: Vec<EventType>,
    seen_by: &impl EventVisibility,
) -> Result<Vec<EventType>, DomainError> {
    if asked.contains(&DELIVERY) {
        return Err(DomainError::invalid(message!(
            "webhooks-a-webhook-cannot-subscribe-to-its",
            "a webhook cannot subscribe to its own deliveries"
        )));
    }
    if asked.iter().any(|event_type| !seen_by.may_see(event_type)) {
        return Err(DomainError::forbidden(message!(
            "webhooks-a-webhook-receives-only-events-the",
            "a webhook receives only events the person setting it up may see"
        )));
    }
    if !asked.is_empty() {
        return Ok(asked);
    }
    let visible: Vec<EventType> = subscribable_events(seen_by)
        .into_iter()
        .map(|entry| entry.event_type)
        .collect();
    if visible.is_empty() {
        return Err(DomainError::invalid(message!(
            "webhooks-the-person-setting-it-up-may",
            "the person setting it up may see no event to send"
        )));
    }
    Ok(visible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::event_type::{CryptoEvent, IdentityEvent};

    /// Someone who may see every event but signing key events.
    struct NoKeys;

    impl EventVisibility for NoKeys {
        fn may_see(&self, event_type: &EventType) -> bool {
            !matches!(event_type, EventType::Crypto(_))
        }
    }

    /// Ann may not see signing key events. Her list offers user
    /// registrations, described in words, but no key event and never the
    /// record of a webhook's own delivery.
    #[test]
    fn the_catalog_lists_what_the_person_may_see_with_its_meaning() {
        let entries = subscribable_events(&NoKeys);
        let names: Vec<&str> = entries.iter().map(CatalogEntry::name).collect();
        let registered = entries
            .iter()
            .find(|entry| entry.event_type() == IdentityEvent::UserRegistered.into())
            .unwrap();

        assert!(!registered.description().is_empty());
        assert!(!names.contains(&CryptoEvent::ALL[0].1));
        assert!(!names.contains(&DELIVERY.as_str()));
    }

    /// An empty subscription list expands to the visible catalog's size
    /// and excludes an event from the hidden signing key category.
    #[test]
    fn an_empty_list_subscribes_to_the_catalog() {
        let subscribed = subscribed(Vec::new(), &NoKeys).unwrap();

        assert_eq!(subscribed.len(), subscribable_events(&NoKeys).len());
        assert!(!subscribed.contains(&CryptoEvent::ALL[0].0.into()));
    }
}
