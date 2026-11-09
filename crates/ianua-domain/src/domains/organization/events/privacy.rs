//! Events about an organization member's consent and the erasure of their
//! data.
//!
//! The erasure events name the member by account id only: the records are
//! permanent, and a name or an address in them would outlive the very data
//! the member asked to have removed.

use time::OffsetDateTime;

use crate::domains::identity::events::privacy::consent_type_text;
use crate::domains::identity::privacy::consent::ConsentTerms;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::organization_event;
use crate::types::{EventLabel, OrgUserId, OrganizationId};

/// The member a record is about, named by `label`.
fn member(org_user_id: &OrgUserId, label: &str) -> Reference {
    Reference::new(RefKind::ORG_USER, org_user_id.to_string(), label)
}

/// The member a record is about, named by account id only.
fn member_by_id(org_user_id: &OrgUserId) -> Reference {
    member(org_user_id, &org_user_id.to_string())
}

/// The payload both consent events carry: whose decision, about which kind
/// of consent and which version of the terms.
fn consent_payload(org_user_id: &OrgUserId, label: &EventLabel, terms: &ConsentTerms) -> EventData {
    EventData::new()
        .reference("org_user", member(org_user_id, label.as_str()))
        .field("consent_type", consent_type_text(terms.consent_type))
        .field("version", terms.version.as_str())
}

/// A member gave their consent to one version of some terms.
#[derive(Debug)]
pub struct OrgUserConsentGranted {
    /// The organization the member belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The member who consented.
    pub(crate) org_user_id: OrgUserId,
    /// How the member is named, taken when they consented.
    pub(crate) org_user_label: EventLabel,
    /// What they consented to, and which version.
    pub(crate) terms: ConsentTerms,
    /// When they consented.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserConsentGranted => crate::types::event_type::OrganizationEvent::OrgUserConsentGranted,
    fn payload(&self) -> EventData {
        consent_payload(&self.org_user_id, &self.org_user_label, &self.terms)
    }
}

/// A member's consent was withdrawn, by them or for them by someone who
/// may update members.
#[derive(Debug)]
pub struct OrgUserConsentRevoked {
    /// The organization the member belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The member whose consent was withdrawn.
    pub(crate) org_user_id: OrgUserId,
    /// How the member is named, taken when it was withdrawn.
    pub(crate) org_user_label: EventLabel,
    /// What was withdrawn, and which version of the terms.
    pub(crate) terms: ConsentTerms,
    /// When it was withdrawn.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserConsentRevoked => crate::types::event_type::OrganizationEvent::OrgUserConsentRevoked,
    fn payload(&self) -> EventData {
        consent_payload(&self.org_user_id, &self.org_user_label, &self.terms)
    }
}

/// A member's data is to be erased, once its grace period is over.
#[derive(Debug)]
pub struct OrgUserErasureRequested {
    /// The organization the member belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The member to be erased.
    pub(crate) org_user_id: OrgUserId,
    /// When deletion is due to start.
    pub(crate) scheduled_at: OffsetDateTime,
    /// When it was asked for.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserErasureRequested => crate::types::event_type::OrganizationEvent::OrgUserErasureRequested,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("org_user", member_by_id(&self.org_user_id))
            .field("scheduled_at", self.scheduled_at.to_string())
    }
}

/// A member's erasure was cancelled during its grace period.
#[derive(Debug)]
pub struct OrgUserErasureCancelled {
    /// The organization the member belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The member who stays.
    pub(crate) org_user_id: OrgUserId,
    /// When it was cancelled.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserErasureCancelled => crate::types::event_type::OrganizationEvent::OrgUserErasureCancelled,
    fn payload(&self) -> EventData {
        EventData::new().reference("org_user", member_by_id(&self.org_user_id))
    }
}

/// A legal hold paused a member's erasure. It waits, past its grace
/// period, until the hold is lifted.
#[derive(Debug)]
pub struct OrgUserErasureHeld {
    /// The organization the member belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The member whose erasure waits.
    pub(crate) org_user_id: OrgUserId,
    /// When it was held.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserErasureHeld => crate::types::event_type::OrganizationEvent::OrgUserErasureHeld,
    fn payload(&self) -> EventData {
        EventData::new().reference("org_user", member_by_id(&self.org_user_id))
    }
}

/// A legal hold on a member's erasure was lifted.
#[derive(Debug)]
pub struct OrgUserErasureReleased {
    /// The organization the member belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The member whose erasure waits again.
    pub(crate) org_user_id: OrgUserId,
    /// When it was released.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserErasureReleased => crate::types::event_type::OrganizationEvent::OrgUserErasureReleased,
    fn payload(&self) -> EventData {
        EventData::new().reference("org_user", member_by_id(&self.org_user_id))
    }
}

/// Deleting a member's data started, after the grace period.
#[derive(Debug)]
pub struct OrgUserErasureStarted {
    /// The organization the member belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The member being erased.
    pub(crate) org_user_id: OrgUserId,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserErasureStarted => crate::types::event_type::OrganizationEvent::OrgUserErasureStarted,
    fn payload(&self) -> EventData {
        EventData::new().reference("org_user", member_by_id(&self.org_user_id))
    }
}

/// All of a member's data was deleted for good.
#[derive(Debug)]
pub struct OrgUserErasureCompleted {
    /// The organization the member belonged to.
    pub(crate) organization_id: OrganizationId,
    /// The member erased.
    pub(crate) org_user_id: OrgUserId,
    /// When it finished.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserErasureCompleted => crate::types::event_type::OrganizationEvent::OrgUserErasureCompleted,
    fn payload(&self) -> EventData {
        EventData::new().reference("org_user", member_by_id(&self.org_user_id))
    }
}

/// Deleting a member's data stopped part way, so some of it may be gone.
#[derive(Debug)]
pub struct OrgUserErasureFailed {
    /// The organization the member belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The member partly erased.
    pub(crate) org_user_id: OrgUserId,
    /// When it failed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserErasureFailed => crate::types::event_type::OrganizationEvent::OrgUserErasureFailed,
    fn payload(&self) -> EventData {
        EventData::new().reference("org_user", member_by_id(&self.org_user_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::identity::privacy::consent::ConsentType;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;
    use crate::types::Label;

    /// Ada withdraws her marketing consent. The record names her, the kind
    /// of consent and the version.
    #[test]
    fn a_consent_record_names_the_member_the_kind_and_the_version() {
        let ada = OrgUserId::new();
        let event = OrgUserConsentRevoked {
            organization_id: OrganizationId::new(),
            org_user_id: ada,
            org_user_label: EventLabel::of("ada@acme.com"),
            terms: ConsentTerms {
                consent_type: ConsentType::Marketing,
                version: Label::new("version", "mkt-2026").unwrap(),
            },
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("consent_type"), Some("marketing"));
        assert_eq!(payload.get("version"), Some("mkt-2026"));
        let Some(FieldValue::Reference(reference)) = payload.value("org_user") else {
            panic!("the record names no member");
        };
        assert_eq!(reference.id(), ada.to_string());
    }

    /// Ada's erasure completes. The record names her by account id only,
    /// never by the name or address the erasure removed.
    #[test]
    fn an_erasure_record_names_the_member_by_id_only() {
        let ada = OrgUserId::new();
        let event = OrgUserErasureCompleted {
            organization_id: OrganizationId::new(),
            org_user_id: ada,
            occurred_at: crate::shared::clock::now(),
        };

        let Some(FieldValue::Reference(reference)) = event.payload().value("org_user").cloned()
        else {
            panic!("the record names no member");
        };
        assert_eq!(reference.label(), ada.to_string());
    }
}
