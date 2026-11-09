//! Events about just-in-time access requests: asked for, approved, denied,
//! withdrawn or left to run out.

use time::OffsetDateTime;

use crate::domains::authorization::access_request::AskedAccess;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{AccessRequestId, EventLabel, Lifetime, PrincipalRef, Text};

/// Someone asked for a role or a group for a while.
#[derive(Debug)]
pub struct AccessRequested {
    /// The application for temporary membership that now awaits a decision.
    pub(crate) request_id: AccessRequestId,
    /// Who asked, and would hold it.
    pub(crate) holder: PrincipalRef,
    /// The asker's display label, for the audit trail.
    pub(crate) holder_label: EventLabel,
    /// The role or group asked for.
    pub(crate) asked: AskedAccess,
    /// Its name, for the audit trail.
    pub(crate) asked_label: EventLabel,
    /// Why they asked.
    pub(crate) reason: Text,
    /// How long they asked for it.
    pub(crate) length: Lifetime,
    /// When they asked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessRequested => crate::types::event_type::AuthorizationEvent::AccessRequested,
    fn payload(&self) -> EventData {
        let (key, asked) = asked_reference(self.asked, &self.asked_label);
        EventData::new()
            .field("request", self.request_id.to_string())
            .reference("holder", holder_reference(&self.holder, &self.holder_label))
            .reference(key, asked)
            .field("reason", self.reason.to_string())
            .field("duration", self.length.whole_seconds().to_string())
    }
}

/// A request for access was approved: its asker holds what they asked for
/// until `until`.
#[derive(Debug)]
pub struct AccessRequestApproved {
    /// The application whose approved access now has an expiry.
    pub(crate) request_id: AccessRequestId,
    /// Who asked, and now holds it.
    pub(crate) holder: PrincipalRef,
    /// The holder's display label, for the audit trail.
    pub(crate) holder_label: EventLabel,
    /// The role or group given.
    pub(crate) asked: AskedAccess,
    /// Its name, for the audit trail.
    pub(crate) asked_label: EventLabel,
    /// When the access ends.
    pub(crate) until: OffsetDateTime,
    /// When it was approved.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessRequestApproved => crate::types::event_type::AuthorizationEvent::AccessRequestApproved,
    fn payload(&self) -> EventData {
        let (key, asked) = asked_reference(self.asked, &self.asked_label);
        EventData::new()
            .field("request", self.request_id.to_string())
            .reference("holder", holder_reference(&self.holder, &self.holder_label))
            .reference(key, asked)
            .field("expires_at", self.until.to_string())
    }
}

/// A request for access was denied.
#[derive(Debug)]
pub struct AccessRequestDenied {
    /// The application whose requested role or group was refused.
    pub(crate) request_id: AccessRequestId,
    /// Who asked.
    pub(crate) holder: PrincipalRef,
    /// The asker's display label, for the audit trail.
    pub(crate) holder_label: EventLabel,
    /// The role or group refused.
    pub(crate) asked: AskedAccess,
    /// Its name, for the audit trail.
    pub(crate) asked_label: EventLabel,
    /// When it was denied.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessRequestDenied => crate::types::event_type::AuthorizationEvent::AccessRequestDenied,
    fn payload(&self) -> EventData {
        let (key, asked) = asked_reference(self.asked, &self.asked_label);
        EventData::new()
            .field("request", self.request_id.to_string())
            .reference("holder", holder_reference(&self.holder, &self.holder_label))
            .reference(key, asked)
    }
}

/// The person who asked for access withdrew the request.
#[derive(Debug)]
pub struct AccessRequestCancelled {
    /// The application withdrawn by its prospective holder.
    pub(crate) request_id: AccessRequestId,
    /// Who asked, and withdrew it.
    pub(crate) holder: PrincipalRef,
    /// The asker's display label, for the audit trail.
    pub(crate) holder_label: EventLabel,
    /// When it was withdrawn.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessRequestCancelled => crate::types::event_type::AuthorizationEvent::AccessRequestCancelled,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("request", self.request_id.to_string())
            .reference("holder", holder_reference(&self.holder, &self.holder_label))
    }
}

/// Nobody answered a request for access before it ran out.
#[derive(Debug)]
pub struct AccessRequestExpired {
    /// The application that reached its deadline without a decision.
    pub(crate) request_id: AccessRequestId,
    /// Who asked.
    pub(crate) holder: PrincipalRef,
    /// The asker's display label, for the audit trail.
    pub(crate) holder_label: EventLabel,
    /// When it ran out.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessRequestExpired => crate::types::event_type::AuthorizationEvent::AccessRequestExpired,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("request", self.request_id.to_string())
            .reference("holder", holder_reference(&self.holder, &self.holder_label))
    }
}

/// The longest a tenant's people may ask for access changed.
///
/// A longer limit lets everyone ask for more, so the record keeps the limit
/// before and after.
#[derive(Debug)]
pub struct AccessRequestPolicyChanged {
    /// The longest one could ask for before.
    pub(crate) previous: Lifetime,
    /// The longest one may ask for now.
    pub(crate) current: Lifetime,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessRequestPolicyChanged => crate::types::event_type::AuthorizationEvent::AccessRequestPolicyChanged,
    fn payload(&self) -> EventData {
        EventData::new().change(
            "duration",
            self.previous.whole_seconds().to_string(),
            self.current.whole_seconds().to_string(),
        )
    }
}

/// The asker as a reference of their own kind.
fn holder_reference(holder: &PrincipalRef, label: &EventLabel) -> Reference {
    Reference::new(holder.ref_kind(), holder.id().to_string(), label.as_str())
}

/// The key and reference the role or group asked for is recorded under.
fn asked_reference(asked: AskedAccess, label: &EventLabel) -> (&'static str, Reference) {
    match asked {
        AskedAccess::Role(role) => (
            "role",
            Reference::new(RefKind::ROLE, role.to_string(), label.as_str()),
        ),
        AskedAccess::Group(group) => (
            "group",
            Reference::new(RefKind::GROUP, group.to_string(), label.as_str()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;
    use crate::types::{GroupId, UserId};

    /// Ann asks for the Production group for two hours. The record names
    /// her, the group by its kind, her reason and the length asked.
    #[test]
    fn a_request_records_who_asked_for_what_and_why() {
        let event = AccessRequested {
            request_id: AccessRequestId::new(),
            holder: PrincipalRef::User(UserId::new()),
            holder_label: EventLabel::of("ann@acme.test"),
            asked: AskedAccess::Group(GroupId::new()),
            asked_label: EventLabel::of("Production"),
            reason: Text::new("reason", "INC-42").unwrap(),
            length: Lifetime::seconds(7200).unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        let Some(FieldValue::Reference(group)) = payload.value("group") else {
            panic!("the group is recorded as a reference");
        };
        assert_eq!(group.kind(), RefKind::GROUP);
        assert_eq!(payload.get("reason"), Some("INC-42"));
        assert_eq!(payload.get("duration"), Some("7200"));
    }
}
