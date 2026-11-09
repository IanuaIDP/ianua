//! Events about invitations to join an organization.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::organization_event;
use crate::types::{Email, OrgUserId, OrganizationId};

/// The invited member, named by their address.
fn invitee(org_user_id: &OrgUserId, email: &Email) -> Reference {
    Reference::new(
        RefKind::ORG_USER,
        org_user_id.to_string(),
        email.to_string(),
    )
}

/// An org user was invited to the organization.
#[derive(Debug)]
pub struct OrgUserInvited {
    /// The organization the user was invited to.
    pub(crate) organization_id: OrganizationId,
    /// The invited org user's ID.
    pub(crate) org_user_id: OrgUserId,
    /// The invited user's email.
    pub(crate) email: Email,
    /// When the invitation was sent.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserInvited => crate::types::event_type::OrganizationEvent::OrgUserInvited,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("org_user", invitee(&self.org_user_id, &self.email))
            .field("email", self.email.to_string())
    }
}

/// A closed org user's account was opened again for a new invitation, with
/// the tenant access and the ways in it held withdrawn.
#[derive(Debug)]
pub struct OrgUserReopened {
    /// The organization the account belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The reopened org user's ID.
    pub(crate) org_user_id: OrgUserId,
    /// The address invited again.
    pub(crate) email: Email,
    /// How many tenants the account lost its access to.
    pub(crate) tenants_withdrawn: usize,
    /// How many second factors and passkeys the account lost.
    pub(crate) factors_withdrawn: usize,
    /// When the account was reopened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserReopened => crate::types::event_type::OrganizationEvent::OrgUserReopened,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("org_user", invitee(&self.org_user_id, &self.email))
            .field("email", self.email.to_string())
            .field("tenants_withdrawn", self.tenants_withdrawn.to_string())
            .field("factors_withdrawn", self.factors_withdrawn.to_string())
    }
}

/// An org user accepted their invitation, set a password, and joined.
#[derive(Debug)]
pub struct OrgUserInvitationAccepted {
    /// The organization joined.
    pub(crate) organization_id: OrganizationId,
    /// The email that accepted.
    pub(crate) email: Email,
    /// When the acceptance occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserInvitationAccepted => crate::types::event_type::OrganizationEvent::OrgUserInvitationAccepted,
    fn payload(&self) -> EventData {
        EventData::new().field("email", self.email.to_string())
    }
}

/// An org user invitation was revoked before being accepted.
#[derive(Debug)]
pub struct OrgUserInvitationRevoked {
    /// The organization the invitation belonged to.
    pub(crate) organization_id: OrganizationId,
    /// The org user the invitation was for.
    pub(crate) org_user_id: OrgUserId,
    /// The email that was invited.
    pub(crate) email: Email,
    /// When the revocation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserInvitationRevoked => crate::types::event_type::OrganizationEvent::OrgUserInvitationRevoked,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("org_user", invitee(&self.org_user_id, &self.email))
            .field("email", self.email.to_string())
    }
}

/// An org user invitation was resent with a new token and a new expiry.
#[derive(Debug)]
pub struct OrgUserInvitationResent {
    /// The organization the invitation belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The org user the invitation is for.
    pub(crate) org_user_id: OrgUserId,
    /// The email that was invited.
    pub(crate) email: Email,
    /// When the resend occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserInvitationResent => crate::types::event_type::OrganizationEvent::OrgUserInvitationResent,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("org_user", invitee(&self.org_user_id, &self.email))
            .field("email", self.email.to_string())
    }
}

/// The invited person turned the invitation down from its link.
#[derive(Debug)]
pub struct OrgUserInvitationDeclined {
    /// The organization the invitation belonged to.
    pub(crate) organization_id: OrganizationId,
    /// The org user the invitation was for.
    pub(crate) org_user_id: OrgUserId,
    /// The email that was invited.
    pub(crate) email: Email,
    /// When it was declined.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserInvitationDeclined => crate::types::event_type::OrganizationEvent::OrgUserInvitationDeclined,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("org_user", invitee(&self.org_user_id, &self.email))
            .field("email", self.email.to_string())
    }
}

/// An invitation ran out before anyone answered it.
#[derive(Debug)]
pub struct OrgUserInvitationExpired {
    /// The organization the invitation belonged to.
    pub(crate) organization_id: OrganizationId,
    /// The org user the invitation was for.
    pub(crate) org_user_id: OrgUserId,
    /// The email that was invited.
    pub(crate) email: Email,
    /// When it was marked expired.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserInvitationExpired => crate::types::event_type::OrganizationEvent::OrgUserInvitationExpired,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("org_user", invitee(&self.org_user_id, &self.email))
            .field("email", self.email.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::{DomainEventCore, OrganizationDomainEvent};

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn entity(payload: &EventData, key: &str) -> (RefKind, String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => (
                reference.kind(),
                reference.id().to_owned(),
                reference.label().to_owned(),
            ),
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    /// Invitation, revocation and resend records name the organization,
    /// invited member and address.
    #[test]
    fn the_invitation_events_name_the_member_and_the_address() {
        let org = OrganizationId::new();
        let member = OrgUserId::new();
        let email = "new@acme.com";
        let address = || Email::new(email).unwrap();

        let events: Vec<Box<dyn OrganizationDomainEvent>> = vec![
            Box::new(OrgUserInvited {
                organization_id: org,
                org_user_id: member,
                email: address(),
                occurred_at: now(),
            }),
            Box::new(OrgUserInvitationRevoked {
                organization_id: org,
                org_user_id: member,
                email: address(),
                occurred_at: now(),
            }),
            Box::new(OrgUserInvitationResent {
                organization_id: org,
                org_user_id: member,
                email: address(),
                occurred_at: now(),
            }),
        ];

        assert_invitation_references(events, org, member, email);
    }

    /// Declining, expiry and reopening records keep the organization,
    /// invited member and address.
    #[test]
    fn invitation_outcomes_name_the_member_and_the_address() {
        let org = OrganizationId::new();
        let member = OrgUserId::new();
        let email = "new@acme.com";
        let address = || Email::new(email).unwrap();
        let events: Vec<Box<dyn OrganizationDomainEvent>> = vec![
            Box::new(OrgUserInvitationDeclined {
                organization_id: org,
                org_user_id: member,
                email: address(),
                occurred_at: now(),
            }),
            Box::new(OrgUserInvitationExpired {
                organization_id: org,
                org_user_id: member,
                email: address(),
                occurred_at: now(),
            }),
            Box::new(OrgUserReopened {
                organization_id: org,
                org_user_id: member,
                email: address(),
                tenants_withdrawn: 2,
                factors_withdrawn: 1,
                occurred_at: now(),
            }),
        ];

        assert_invitation_references(events, org, member, email);
    }

    /// Every invitation event must retain the organization and the invitee's identity.
    fn assert_invitation_references(
        events: Vec<Box<dyn OrganizationDomainEvent>>,
        org: OrganizationId,
        member: OrgUserId,
        email: &str,
    ) {
        for event in events {
            let kind = event.event_type();
            let payload = event.payload();
            assert_eq!(event.organization_id(), &org, "{kind}");
            assert_eq!(
                entity(&payload, "org_user"),
                (RefKind::ORG_USER, member.to_string(), email.to_owned()),
                "{kind}"
            );
            assert_eq!(payload.get("email"), Some(email), "{kind}");
        }
    }

    /// `new@acme.com` accepts their own invitation. The record carries that
    /// address and nothing more, since the actor is the invitee.
    #[test]
    fn accepting_an_invitation_records_the_address_that_accepted() {
        let org = OrganizationId::new();

        let event = OrgUserInvitationAccepted {
            organization_id: org,
            email: Email::new("new@acme.com").unwrap(),
            occurred_at: now(),
        };

        assert_eq!(event.organization_id(), &org);
        assert_eq!(event.payload().get("email"), Some("new@acme.com"));
    }
}
