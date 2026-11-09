//! A reader marking notifications in their own inbox read, and what that
//! records.
//!
//! The stores mark notifications read in one statement each, so no
//! notification is loaded and changed. [`InboxRead`] says what was marked,
//! and the record it makes is built here, not by whoever marked it.
//!
//! The record goes to the reader's own trail: a tenant user's read to the
//! tenant's, an organization member's to the organization's, an
//! operator's to the platform's. A tenant user's reads are the tenant's
//! business, not the operators'.

use time::OffsetDateTime;

use crate::domains::notifications::events::{AllNotificationsMarkedRead, NotificationMarkedRead};
use crate::shared::events::data::EventData;
use crate::shared::events::event::{DomainEvent, DomainEventCore, OrganizationDomainEvent};
use crate::shared::events::raised::{TenantEventBody, scoped};
use crate::types::{EventLabel, EventType, NotificationId, OrganizationId, TenantId};

/// Whose inbox was read, which decides whose trail records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxOwner {
    /// Records the read in the recipient's tenant audit trail.
    TenantUser(TenantId),
    /// A member of this organization.
    OrgMember(OrganizationId),
    /// An operator of the platform.
    Operator,
}

/// What a reader marked read in their own inbox.
///
/// The reader is not part of it: they are the record's actor, which the
/// application names when it dispatches the events.
#[derive(Debug)]
pub struct InboxRead(Marked);

#[derive(Debug)]
enum Marked {
    One {
        notification_id: NotificationId,
        label: EventLabel,
    },
    All {
        count: u64,
    },
}

impl InboxRead {
    /// The notification `notification_id` was marked read. `label` is its
    /// title as the reader's inbox shows it, kept so the record stays
    /// readable after the notification is gone.
    #[must_use]
    pub fn one(notification_id: NotificationId, label: EventLabel) -> Self {
        Self(Marked::One {
            notification_id,
            label,
        })
    }

    /// Every notification in the inbox was marked read, `count` of them
    /// changing.
    #[must_use]
    pub fn all(count: u64) -> Self {
        Self(Marked::All { count })
    }

    /// The record of the marking, in the trail of `owner`:
    /// `notifications.notification_read` for one notification,
    /// `notifications.all_notifications_read` with the count for all of
    /// them. The time is now.
    #[must_use]
    pub fn events(self, owner: InboxOwner) -> Vec<DomainEvent> {
        let occurred_at = crate::shared::clock::now();
        let event = match self.0 {
            Marked::One {
                notification_id,
                label,
            } => recorded_for(
                owner,
                NotificationMarkedRead {
                    notification_id,
                    notification_label: label,
                    occurred_at,
                },
            ),
            Marked::All { count } => {
                recorded_for(owner, AllNotificationsMarkedRead { count, occurred_at })
            }
        };
        vec![event]
    }
}

/// `body` as a record in the trail of `owner`.
fn recorded_for<E>(owner: InboxOwner, body: E) -> DomainEvent
where
    E: TenantEventBody + crate::shared::events::event::PlatformDomainEvent + 'static,
{
    match owner {
        InboxOwner::TenantUser(tenant_id) => scoped(tenant_id, body),
        InboxOwner::OrgMember(organization_id) => {
            DomainEvent::organization(Box::new(InOrganization {
                organization_id,
                body: Box::new(body),
            }))
        }
        InboxOwner::Operator => DomainEvent::platform(Box::new(body)),
    }
}

/// A read recorded in an organization's trail.
struct InOrganization {
    organization_id: OrganizationId,
    body: Box<dyn DomainEventCore>,
}

impl DomainEventCore for InOrganization {
    fn event_type(&self) -> EventType {
        self.body.event_type()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.body.occurred_at()
    }

    fn payload(&self) -> EventData {
        self.body.payload()
    }
}

impl OrganizationDomainEvent for InOrganization {
    fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;

    /// Olga, an operator, marks "Signing key rotated" read. One
    /// `notifications.notification_read` is recorded in the platform's
    /// trail, linking the notification by id and title, and naming no
    /// tenant.
    #[test]
    fn reading_one_records_notifications_notification_read() {
        let id = NotificationId::new();

        let events =
            InboxRead::one(id, EventLabel::of("Signing key rotated")).events(InboxOwner::Operator);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "notifications.notification_read"
        );
        assert_eq!(events[0].tenant_id(), None);
        let payload = events[0].payload();
        let Some(FieldValue::Reference(notification)) = payload.value("notification") else {
            panic!("expected a notification reference");
        };
        assert_eq!(notification.id(), id.to_string());
        assert_eq!(notification.label(), "Signing key rotated");
    }

    /// Ann marks her whole inbox read, 42 notifications. One
    /// `notifications.all_notifications_read` is recorded with the count.
    #[test]
    fn reading_all_records_notifications_all_notifications_read() {
        let events = InboxRead::all(42).events(InboxOwner::Operator);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "notifications.all_notifications_read"
        );
        assert_eq!(events[0].payload().get("count"), Some("42"));
    }

    /// Ann, a user of Acme, marks a notification read. The record is in
    /// Acme's trail, where Acme's admins see it, not the operators'.
    #[test]
    fn a_tenant_users_read_is_recorded_in_the_tenants_trail() {
        let acme = TenantId::new();

        let events = InboxRead::all(3).events(InboxOwner::TenantUser(acme));

        assert_eq!(events[0].tenant_id(), Some(&acme));
        assert_eq!(events[0].organization_id(), None);
    }

    /// Bob, a member of the organization, marks a notification read. The
    /// record is in the organization's trail.
    #[test]
    fn an_org_members_read_is_recorded_in_the_organizations_trail() {
        let organization = OrganizationId::new();

        let events = InboxRead::one(NotificationId::new(), EventLabel::of("Tenant created"))
            .events(InboxOwner::OrgMember(organization));

        assert_eq!(events[0].organization_id(), Some(&organization));
        assert_eq!(events[0].tenant_id(), None);
        assert_eq!(
            events[0].event_type().to_string(),
            "notifications.notification_read"
        );
    }
}
