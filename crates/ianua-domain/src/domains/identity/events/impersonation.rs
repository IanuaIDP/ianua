//! Events about a tenant admin acting as one of the tenant's people.
//!
//! The admin is the actor the audit record names. Each event names the
//! person acted as, by account id.

use time::OffsetDateTime;

use crate::domains::identity::events::user_reference;
use crate::domains::identity::impersonation::state::ImpersonationConsent;
use crate::shared::events::data::{EventData, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{Text, UserId};

/// The person acted as, named by account id.
fn person(user_id: &UserId) -> Reference {
    user_reference(user_id, &user_id.to_string())
}

/// A tenant admin asked to act as a person, for a reason.
#[derive(Debug)]
pub struct SupportImpersonationRequested {
    /// The person to act as.
    pub(crate) user_id: UserId,
    /// Why, as the admin wrote it.
    pub(crate) reason: Text,
    /// Whether the person must approve first.
    pub(crate) consent: ImpersonationConsent,
    /// When it was asked for.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SupportImpersonationRequested => crate::types::event_type::IdentityEvent::SupportImpersonationRequested,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("user", person(&self.user_id))
            .field("reason", self.reason.as_str())
            .field("mode", self.consent.as_str())
    }
}

/// A tenant admin may now act as a person, until a time.
#[derive(Debug)]
pub struct SupportImpersonationStarted {
    /// The person acted as.
    pub(crate) user_id: UserId,
    /// When the admin's window ends.
    pub(crate) ends_at: OffsetDateTime,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SupportImpersonationStarted => crate::types::event_type::IdentityEvent::SupportImpersonationStarted,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("user", person(&self.user_id))
            .field("expires_at", self.ends_at.to_string())
    }
}

/// The person refused to let a tenant admin act as them.
#[derive(Debug)]
pub struct SupportImpersonationDeclined {
    /// The person who refused.
    pub(crate) user_id: UserId,
    /// When they refused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SupportImpersonationDeclined => crate::types::event_type::IdentityEvent::SupportImpersonationDeclined,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", person(&self.user_id))
    }
}

/// A tenant admin's acting as a person was ended early or withdrawn, by
/// the admin or the person.
#[derive(Debug)]
pub struct SupportImpersonationEnded {
    /// The person acted as.
    pub(crate) user_id: UserId,
    /// When it ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SupportImpersonationEnded => crate::types::event_type::IdentityEvent::SupportImpersonationEnded,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", person(&self.user_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::event::DomainEventCore;

    /// Support asks to act as Ann because she cannot see her invoices, and
    /// she must approve first. The record keeps the reason and the rule.
    #[test]
    fn a_request_records_its_reason_and_whether_the_person_approves() {
        let event = SupportImpersonationRequested {
            user_id: UserId::new(),
            reason: Text::new("reason", "Ann cannot see her invoices").unwrap(),
            consent: ImpersonationConsent::HolderApproves,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("reason"), Some("Ann cannot see her invoices"));
        assert_eq!(payload.get("mode"), Some("holder_approves"));
    }

    /// A start records when the admin's window ends.
    #[test]
    fn a_start_records_when_it_ends() {
        let ends_at = crate::shared::clock::now();
        let event = SupportImpersonationStarted {
            user_id: UserId::new(),
            ends_at,
            occurred_at: ends_at,
        };

        assert_eq!(
            event.payload().get("expires_at"),
            Some(ends_at.to_string().as_str())
        );
    }
}
