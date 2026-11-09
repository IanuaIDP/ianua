//! A change to the values a user holds under the tenant's attributes, as
//! the audit trail records it.
//!
//! The values are written straight to storage, one at a time or all of a
//! user's at once, with no aggregate loaded to change. So the change is an
//! operation of its own: the application makes it once the write was
//! allowed, stores the values, and then takes what it raised.

use std::marker::PhantomData;

use crate::domains::identity::attribute::key::AttributeKey;
use crate::domains::identity::attribute::namespace::AttributeNamespace;
use crate::domains::identity::events::account::{UserMetadataDeleted, UserMetadataUpdated};
use crate::isolation::scope::TenantScope;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor, TenantEventBody};
use crate::types::{EventLabel, UserId};

/// One change to a user's stored attribute values.
#[derive(Debug)]
pub struct MetadataChange<T: TenantScope> {
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> MetadataChange<T> {
    /// The value `user_id` holds under `namespace` and `key` was set or
    /// cleared. Raises `identity.user_metadata_updated`, naming the user as
    /// `user_label`.
    #[must_use]
    pub fn one_value(
        user_id: UserId,
        user_label: EventLabel,
        namespace: AttributeNamespace,
        key: AttributeKey,
    ) -> Self {
        Self::raising(UserMetadataUpdated {
            user_id,
            user_label,
            namespace,
            key,
            occurred_at: crate::shared::clock::now(),
        })
    }

    /// Every value `user_id` held was deleted. Raises
    /// `identity.user_metadata_deleted`, naming the user as `user_label`.
    #[must_use]
    pub fn every_value(user_id: UserId, user_label: EventLabel) -> Self {
        Self::raising(UserMetadataDeleted {
            user_id,
            user_label,
            occurred_at: crate::shared::clock::now(),
        })
    }

    fn raising(event: impl TenantEventBody + 'static) -> Self {
        let mut raised = Raised::default();
        raised.raise(event);
        Self {
            raised,
            _scope: PhantomData,
        }
    }
}

impl<T: TenantScope> Raises for MetadataChange<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::{raised, raised_names};

    /// Ann sets Ada's `employee_number`. The change names Ada and the key.
    #[test]
    fn setting_one_value_raises_identity_metadata_updated() {
        let mut change = MetadataChange::<ResolvedTenant>::one_value(
            UserId::new(),
            EventLabel::of("Ada (ada@acme.com)"),
            AttributeNamespace::App,
            AttributeKey::new("employee_number").unwrap(),
        );

        let events = raised(&mut change);

        assert_eq!(
            events[0].event_type().to_string(),
            "identity.metadata_updated"
        );
        assert_eq!(events[0].payload().get("key"), Some("employee_number"));
    }

    /// Ann deletes every value Ada holds. The change is raised once, and
    /// taking it again finds nothing.
    #[test]
    fn deleting_every_value_raises_identity_metadata_deleted_once() {
        let mut change = MetadataChange::<ResolvedTenant>::every_value(
            UserId::new(),
            EventLabel::of("Ada (ada@acme.com)"),
        );

        assert_eq!(raised_names(&mut change), ["identity.metadata_deleted"]);
        assert!(raised_names(&mut change).is_empty());
    }
}
