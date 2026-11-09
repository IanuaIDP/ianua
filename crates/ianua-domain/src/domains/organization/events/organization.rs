//! Events about the organization itself: creation, status, names and plan.

use time::OffsetDateTime;

use crate::domains::organization::billing::plan::OrganizationPlan;
use crate::domains::organization::status::OrganizationStatus;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::organization_event;
use crate::types::{DisplayName, Email, EventLabel, Label, OrganizationId, TenantId};

/// A new organization was created.
#[derive(Debug)]
pub(crate) struct OrganizationCreated {
    /// The newly created organization.
    pub(crate) organization_id: OrganizationId,
    /// Organization name at the time of creation.
    pub(crate) name: Label,
    /// When the organization was created.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrganizationCreated => crate::types::event_type::OrganizationEvent::Created,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("organization_id", self.organization_id.to_string())
            .field("name", self.name.to_string())
    }
}

/// An organization's status changed.
#[derive(Debug)]
pub(crate) struct OrganizationStatusChanged {
    /// The organization whose status changed.
    pub(crate) organization_id: OrganizationId,
    /// The previous status.
    pub(crate) from: OrganizationStatus,
    /// The new status.
    pub(crate) to: OrganizationStatus,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrganizationStatusChanged => crate::types::event_type::OrganizationEvent::StatusChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("organization_id", self.organization_id.to_string())
            .change(
                "status",
                self.from.as_str(),
                self.to.as_str(),
            )
    }
}

/// A tenant was created within an organization.
#[derive(Debug)]
pub(crate) struct OrganizationTenantCreated {
    /// The organization that owns the new tenant.
    pub(crate) organization_id: OrganizationId,
    /// The newly created tenant.
    pub(crate) tenant_id: TenantId,
    /// The tenant's human label as it was when the event fired.
    pub(crate) tenant_label: EventLabel,
    /// When the tenant was created.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrganizationTenantCreated => crate::types::event_type::OrganizationEvent::TenantCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("organization_id", self.organization_id.to_string())
            .reference(
                "tenant",
                Reference::new(
                    RefKind::TENANT,
                    self.tenant_id.to_string(),
                    self.tenant_label.as_str(),
                ),
            )
    }
}

/// The organization was renamed.
#[derive(Debug)]
pub(crate) struct OrganizationRenamed {
    /// The organization that was renamed.
    pub(crate) organization_id: OrganizationId,
    /// The previous name.
    pub(crate) old_name: Label,
    /// The replacement internal label captured in the audit record.
    pub(crate) new_name: Label,
    /// When the rename occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrganizationRenamed => crate::types::event_type::OrganizationEvent::Renamed,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("organization_id", self.organization_id.to_string())
            .change("name", self.old_name.to_string(), self.new_name.to_string())
    }
}

/// The organization's contact email was changed.
#[derive(Debug)]
pub(crate) struct OrganizationContactEmailChanged {
    /// The organization whose email changed.
    pub(crate) organization_id: OrganizationId,
    /// The previous contact email.
    pub(crate) old_email: Email,
    /// The new contact email.
    pub(crate) new_email: Email,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrganizationContactEmailChanged => crate::types::event_type::OrganizationEvent::ContactEmailChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("organization_id", self.organization_id.to_string())
            .change(
                "email",
                self.old_email.to_string(),
                self.new_email.to_string(),
            )
    }
}

/// The organization's display name was changed.
#[derive(Debug)]
pub(crate) struct OrganizationDisplayNameChanged {
    /// The organization whose display name changed.
    pub(crate) organization_id: OrganizationId,
    /// The previous display name.
    pub(crate) old_display_name: DisplayName,
    /// The replacement public label captured in the audit record.
    pub(crate) new_display_name: DisplayName,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrganizationDisplayNameChanged => crate::types::event_type::OrganizationEvent::DisplayNameChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("organization_id", self.organization_id.to_string())
            .change(
                "display_name",
                self.old_display_name.to_string(),
                self.new_display_name.to_string(),
            )
    }
}

/// The organization's subscription plan was changed.
///
/// The new tier brings its own [`PlanLimits`](crate::domains::organization::billing::plan::PlanLimits).
#[derive(Debug)]
pub(crate) struct OrgPlanChanged {
    /// The organization whose plan changed.
    pub(crate) organization_id: OrganizationId,
    /// The previous subscription tier.
    pub(crate) old_plan: OrganizationPlan,
    /// The new subscription tier.
    pub(crate) new_plan: OrganizationPlan,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgPlanChanged => crate::types::event_type::OrganizationEvent::PlanChanged,
    fn payload(&self) -> EventData {
        EventData::new().change("plan", self.old_plan.to_string(), self.new_plan.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::{DomainEventCore, OrganizationDomainEvent};
    use crate::test_support::builders::label;

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

    fn change(payload: &EventData, key: &str) -> (Option<String>, Option<String>) {
        match payload.value(key) {
            Some(FieldValue::Change(change)) => (
                change.from().map(str::to_owned),
                change.to().map(str::to_owned),
            ),
            other => panic!("{key} is not a change: {other:?}"),
        }
    }

    /// Acme moves from Free to Business. The record's type is
    /// `organization.plan_changed`.
    #[test]
    fn plan_changed_event_has_correct_type() {
        let event = OrgPlanChanged {
            organization_id: OrganizationId::new(),
            old_plan: OrganizationPlan::Free,
            new_plan: OrganizationPlan::Business,
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(event.event_type().as_str(), "organization.plan_changed");
    }

    /// Acme moves from Starter to Business. The record holds `starter` as the
    /// old plan and `business` as the new one.
    #[test]
    fn plan_changed_event_captures_transition() {
        let event = OrgPlanChanged {
            organization_id: OrganizationId::new(),
            old_plan: OrganizationPlan::Starter,
            new_plan: OrganizationPlan::Business,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(plan)) = payload.value("plan") else {
            panic!("expected a plan change");
        };
        assert_eq!(plan.from(), Some("starter"));
        assert_eq!(plan.to(), Some("business"));
    }

    /// Acme changes its plan. The record names Acme as its organization, so it
    /// lands in Acme's audit trail only.
    #[test]
    fn plan_changed_carries_organization_id() {
        let org_id = OrganizationId::new();
        let event = OrgPlanChanged {
            organization_id: org_id,
            old_plan: OrganizationPlan::Free,
            new_plan: OrganizationPlan::Starter,
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(*event.organization_id(), org_id);
    }

    /// Acme creates a tenant called Production. The record names that tenant
    /// as "Production" and carries Acme's id.
    #[test]
    fn a_created_tenant_is_named_in_its_record() {
        let org = OrganizationId::new();
        let tenant = TenantId::new();

        let event = OrganizationTenantCreated {
            organization_id: org,
            tenant_id: tenant,
            tenant_label: EventLabel::of("Production"),
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(event.organization_id(), &org);
        assert_eq!(
            entity(&payload, "tenant"),
            (RefKind::TENANT, tenant.to_string(), "Production".to_owned())
        );
        assert_eq!(
            payload.get("organization_id"),
            Some(org.to_string().as_str())
        );
    }

    /// Acme is suspended and renamed. Each record holds both the old and new value.
    #[test]
    fn the_organization_settings_changes_record_both_values() {
        let org = OrganizationId::new();
        let status = OrganizationStatusChanged {
            organization_id: org,
            from: OrganizationStatus::Active,
            to: OrganizationStatus::Suspended,
            occurred_at: now(),
        };
        let renamed = OrganizationRenamed {
            organization_id: org,
            old_name: label("Acme"),
            new_name: label("Acme Corp"),
            occurred_at: now(),
        };

        assert_eq!(
            change(&status.payload(), "status"),
            (Some("active".to_owned()), Some("suspended".to_owned())),
            "the status renders as the enum names it, unlike the lower-cased plan"
        );
        assert_eq!(
            change(&renamed.payload(), "name"),
            (Some("Acme".to_owned()), Some("Acme Corp".to_owned()))
        );
    }

    /// A contact change retains both mailboxes and the organization that changed them.
    #[test]
    fn contact_changes_keep_both_addresses_and_the_organization() {
        let org = OrganizationId::new();
        let email = OrganizationContactEmailChanged {
            organization_id: org,
            old_email: Email::new("ops@acme.com").unwrap(),
            new_email: Email::new("security@acme.com").unwrap(),
            occurred_at: now(),
        };
        assert_eq!(
            change(&email.payload(), "email"),
            (
                Some("ops@acme.com".to_owned()),
                Some("security@acme.com".to_owned())
            )
        );
        assert_eq!(email.organization_id(), &org);
    }

    /// A display-name change retains both names and the organization that changed them.
    #[test]
    fn display_name_changes_keep_both_names_and_the_organization() {
        let org = OrganizationId::new();
        let limits = crate::shared::config::DisplayNameLimits::default();
        let display_name = OrganizationDisplayNameChanged {
            organization_id: org,
            old_display_name: DisplayName::new("Acme", &limits).unwrap(),
            new_display_name: DisplayName::new("Acme Corp", &limits).unwrap(),
            occurred_at: now(),
        };
        assert_eq!(
            change(&display_name.payload(), "display_name"),
            (Some("Acme".to_owned()), Some("Acme Corp".to_owned()))
        );
        assert_eq!(display_name.organization_id(), &org);
    }

    /// Acme is created. The record carries the name "Acme" and Acme's id.
    #[test]
    fn creating_an_organization_records_its_name() {
        let org = OrganizationId::new();

        let event = OrganizationCreated {
            organization_id: org,
            name: label("Acme"),
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(event.organization_id(), &org);
        assert_eq!(payload.get("name"), Some("Acme"));
        assert_eq!(
            payload.get("organization_id"),
            Some(org.to_string().as_str())
        );
    }
}
