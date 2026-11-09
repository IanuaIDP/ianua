//! Events about invitations to join a tenant.

use time::OffsetDateTime;

use crate::domains::identity::events::user_reference;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::{Email, EventLabel, UserId};

/// An admin or a directory sync invited a person to a tenant.
///
/// The account starts `Invited` and cannot sign in until it is activated,
/// such as by accepting the invitation.
#[derive(Debug)]
pub struct UserInvited {
    /// The new user.
    pub(crate) user_id: UserId,
    /// The email address the invitation was sent to.
    pub(crate) email: Email,
    /// When the invitation was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserInvited => crate::types::event_type::IdentityEvent::UserInvited,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.email.as_str()))
    }
}

/// A user accepted an invitation and activated their account.
#[derive(Debug)]
pub struct InvitationAccepted {
    /// When the invitation was accepted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    InvitationAccepted => crate::types::event_type::IdentityEvent::InvitationAccepted,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// An invitation expired without being accepted.
///
/// The link has stopped working. A new invitation must be sent if the
/// person still needs access.
#[derive(Debug)]
pub struct InvitationExpired {
    /// The user the invitation was for.
    pub(crate) user_id: UserId,
    /// The invited user's label when it expired.
    pub(crate) user_label: EventLabel,
    /// When the invitation expired.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    InvitationExpired => crate::types::event_type::IdentityEvent::InvitationExpired,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.user_label.as_str()))
    }
}

/// An invitation was revoked before being accepted.
///
/// The link has stopped working, so the invited person cannot use it to
/// activate their account.
#[derive(Debug)]
pub struct InvitationRevoked {
    /// The user the invitation was for.
    pub(crate) user_id: UserId,
    /// The invited user's label when it was revoked.
    pub(crate) user_label: EventLabel,
    /// When it was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    InvitationRevoked => crate::types::event_type::IdentityEvent::InvitationRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.user_label.as_str()))
    }
}

/// The invited person turned an invitation down from its link.
#[derive(Debug)]
pub struct InvitationDeclined {
    /// The user the invitation was for.
    pub(crate) user_id: UserId,
    /// The invited user's label when it was declined.
    pub(crate) user_label: EventLabel,
    /// When it was declined.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    InvitationDeclined => crate::types::event_type::IdentityEvent::InvitationDeclined,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.user_label.as_str()))
    }
}

/// An invitation was sent again with a new link and a later expiry.
#[derive(Debug)]
pub struct InvitationResent {
    /// The user the invitation was for.
    pub(crate) user_id: UserId,
    /// The invited user's label when it was resent.
    pub(crate) user_label: EventLabel,
    /// When it was resent.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    InvitationResent => crate::types::event_type::IdentityEvent::InvitationResent,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.user_label.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::identity::events::account::UserEmailVerified;
    use crate::domains::identity::events::privacy::ErasureCancelled;
    use crate::shared::events::data::{FieldValue, RefKind, Reference};
    use crate::shared::events::event::DomainEventCore;

    fn expect_reference(payload: &EventData, key: &str) -> Reference {
        let Some(FieldValue::Reference(reference)) = payload.value(key) else {
            panic!("expected a reference at {key}");
        };
        reference.clone()
    }

    /// Bob is invited. The event refers to him as a user by id, labelled
    /// bob@example.com.
    #[test]
    fn invited_event_references_the_invitee_labelled_by_email() {
        let invitee = UserId::new();
        let event = UserInvited {
            user_id: invitee,
            email: Email::new("bob@example.com").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        let reference = expect_reference(&event.payload(), "user");

        assert_eq!(reference.kind(), RefKind::USER);
        assert_eq!(reference.id(), invitee.to_string());
        assert_eq!(reference.label(), "bob@example.com");
    }

    /// Bob is invited by an admin. The payload holds only Bob. The admin is
    /// the actor and is already on the audit record.
    #[test]
    fn invited_event_omits_the_inviter_who_is_the_actor() {
        let event = UserInvited {
            user_id: UserId::new(),
            email: Email::new("bob@example.com").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert!(payload.value("invited_by").is_none());
        assert_eq!(payload.len(), 1);
    }

    /// A user verifies their address, accepts an invitation or cancels their
    /// erasure. Each event has an empty payload, since the user is the actor.
    #[test]
    fn self_service_events_carry_no_payload_beyond_the_actor() {
        let now = crate::shared::clock::now();

        assert!(UserEmailVerified { occurred_at: now }.payload().is_empty());
        assert!(InvitationAccepted { occurred_at: now }.payload().is_empty());
        assert!(ErasureCancelled { occurred_at: now }.payload().is_empty());
    }

    /// Ada's invitation expires, is revoked and is resent. Each event refers
    /// to her account. Accepting is Ada acting, so it
    /// has an empty payload.
    #[test]
    fn the_invitation_events_name_the_account_they_concern() {
        let user = UserId::new();

        let accepted = InvitationAccepted {
            occurred_at: crate::shared::clock::now(),
        };
        assert!(accepted.payload().is_empty());

        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(InvitationExpired {
                user_id: user,
                user_label: EventLabel::of("ada@acme.com"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(InvitationRevoked {
                user_id: user,
                user_label: EventLabel::of("ada@acme.com"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(InvitationResent {
                user_id: user,
                user_label: EventLabel::of("ada@acme.com"),
                occurred_at: crate::shared::clock::now(),
            }),
        ];

        for event in events {
            let kind = event.event_type();
            let reference = expect_reference(&event.payload(), "user");
            assert_eq!(reference.id(), user.to_string(), "{kind}");
            assert_eq!(reference.label(), "ada@acme.com", "{kind}");
        }
    }
}
