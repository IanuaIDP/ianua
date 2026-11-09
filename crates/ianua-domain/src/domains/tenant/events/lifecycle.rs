//! Events about a tenant's life: provisioning, status, settings and deletion.
//!
//! The tenant raises them itself as it changes, its setup raises a failed
//! step ([`InfraFailed`]), and its teardown raises its end
//! (`TenantTornDown`) or a failed step ([`TeardownFailed`]). None is ever
//! raised again to restart work: the record would say it happened twice.

use time::OffsetDateTime;

use crate::domains::tenant::compliance::CompliancePosture;
use crate::domains::tenant::environment::TenantEnvironment;
use crate::domains::tenant::hosts::ReadableAddress;
use crate::domains::tenant::lifecycle::EarlyDeletion;
use crate::domains::tenant::status::TenantStatus;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{
    DisplayName, Email, EventLabel, Locale, TenantId, TenantSlug, Timezone, UntrustedText,
};

/// A new tenant has been created and is awaiting infrastructure setup.
///
/// Triggers provisioning of default roles, auth config, signing keys,
/// and other tenant-scoped resources.
#[derive(Debug)]
pub(crate) struct TenantProvisioned {
    /// The newly created tenant, which the payload links to.
    pub(crate) tenant_id: TenantId,
    /// The tenant's URL slug.
    pub(crate) slug: TenantSlug,
    /// Tenant name at the time of provisioning.
    pub(crate) display_name: DisplayName,
    /// When the tenant was provisioned.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantProvisioned => crate::types::event_type::TenantEvent::Provisioned,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "tenant",
                Reference::new(
                    RefKind::TENANT,
                    self.tenant_id.to_string(),
                    self.display_name.to_string(),
                ),
            )
            .field("slug", self.slug.to_string())
            .field("display_name", self.display_name.to_string())
    }
}

/// A tenant's lifecycle status has changed.
///
/// Covers every move: activation, suspension, reactivation, archival and
/// deletion. Handlers read `to` to decide what to do, for example end
/// sessions on suspension.
#[derive(Debug)]
pub(crate) struct TenantStatusChanged {
    /// The tenant whose status changed, which the payload links to.
    pub(crate) tenant_id: TenantId,
    /// The tenant's display name when the transition occurred.
    pub(crate) tenant_label: EventLabel,
    /// The previous lifecycle status.
    pub(crate) from: TenantStatus,
    /// The new lifecycle status.
    pub(crate) to: TenantStatus,
    /// When the transition occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantStatusChanged => crate::types::event_type::TenantEvent::StatusChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "tenant",
                Reference::new(
                    RefKind::TENANT,
                    self.tenant_id.to_string(),
                    self.tenant_label.as_str(),
                ),
            )
            .change("status", self.from.to_string(), self.to.to_string())
    }
}

/// A tenant's display name has been updated.
///
/// Both old and new names are captured for the audit trail.
#[derive(Debug)]
pub struct TenantRenamed {
    /// The previous display name.
    pub(crate) old_name: DisplayName,
    /// The new display name.
    pub(crate) new_name: DisplayName,
    /// When the rename occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantRenamed => crate::types::event_type::TenantEvent::Renamed,
    fn payload(&self) -> EventData {
        EventData::new().change("name", self.old_name.to_string(), self.new_name.to_string())
    }
}

/// A tenant's contact email was changed.
#[derive(Debug)]
pub struct TenantContactEmailChanged {
    /// The previous contact email.
    pub(crate) old_email: Email,
    /// The new contact email.
    pub(crate) new_email: Email,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantContactEmailChanged => crate::types::event_type::TenantEvent::ContactEmailChanged,
    fn payload(&self) -> EventData {
        EventData::new().change(
            "email",
            self.old_email.to_string(),
            self.new_email.to_string(),
        )
    }
}

/// A tenant's default timezone was changed.
#[derive(Debug)]
pub struct TenantTimezoneChanged {
    /// The previous timezone.
    pub(crate) old_timezone: Timezone,
    /// The replacement default used when local times need interpretation.
    pub(crate) new_timezone: Timezone,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantTimezoneChanged => crate::types::event_type::TenantEvent::TimezoneChanged,
    fn payload(&self) -> EventData {
        EventData::new().change(
            "timezone",
            self.old_timezone.to_string(),
            self.new_timezone.to_string(),
        )
    }
}

/// A tenant's default locale was changed.
#[derive(Debug)]
pub struct TenantLocaleChanged {
    /// The previous locale.
    pub(crate) old_locale: Locale,
    /// The replacement default used when a person has no language preference.
    pub(crate) new_locale: Locale,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantLocaleChanged => crate::types::event_type::TenantEvent::LocaleChanged,
    fn payload(&self) -> EventData {
        EventData::new().change(
            "locale",
            self.old_locale.to_string(),
            self.new_locale.to_string(),
        )
    }
}

/// A tenant was relabelled as serving another stage of its product, such
/// as staging instead of production.
#[derive(Debug)]
pub(crate) struct TenantEnvironmentChanged {
    /// The stage it served before.
    pub(crate) old_environment: TenantEnvironment,
    /// The stage it serves now.
    pub(crate) new_environment: TenantEnvironment,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantEnvironmentChanged => crate::types::event_type::TenantEvent::EnvironmentChanged,
    fn payload(&self) -> EventData {
        EventData::new().change(
            "environment",
            self.old_environment.as_str(),
            self.new_environment.as_str(),
        )
    }
}

/// A tenant opted into or out of publishing its readable platform name.
#[derive(Debug)]
pub(crate) struct TenantReadableAddressChanged {
    /// Whether the readable name was enabled before the request.
    pub(crate) before: ReadableAddress,
    /// Whether the readable name is now enabled.
    pub(crate) after: ReadableAddress,
    /// When the choice changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantReadableAddressChanged => crate::types::event_type::TenantEvent::ReadableAddressChanged,
    fn payload(&self) -> EventData {
        EventData::new().change("readable_address", self.before.as_str(), self.after.as_str())
    }
}

/// A tenant's compliance posture was changed: where its data must stay,
/// how long its audit events are kept, or whether operators may act as its
/// users.
///
/// It records all three before and after, so the audit trail shows exactly
/// what was given up. A shorter retention or allowing impersonation is the
/// kind of change a reviewer looks for.
#[derive(Debug)]
pub(crate) struct TenantComplianceChanged {
    /// The posture before the change.
    pub(crate) before: CompliancePosture,
    /// The posture after the change.
    pub(crate) after: CompliancePosture,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantComplianceChanged => crate::types::event_type::TenantEvent::ComplianceChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .change(
                "data_residency",
                self.before.data_residency().as_str(),
                self.after.data_residency().as_str(),
            )
            .change(
                "audit_retention_days",
                self.before.audit_retention_days().to_string(),
                self.after.audit_retention_days().to_string(),
            )
            .change(
                "operator_impersonation",
                self.before.operator_impersonation().as_str(),
                self.after.operator_impersonation().as_str(),
            )
    }
}

/// A step of a tenant's setup failed for good, so the setup stopped.
///
/// The tenant's setup raises it, naming the step and why it failed. The
/// tenant stays provisioning; an operator fixes the cause and sets it up
/// again.
#[derive(Debug)]
pub struct InfraFailed {
    /// The step that failed, as the setup names it.
    pub(crate) step: &'static str,
    /// Why it failed, as the step reported it.
    pub(crate) reason: UntrustedText,
    /// When the failure occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    InfraFailed => crate::types::event_type::TenantEvent::InfraFailed,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("step", self.step)
            .field("reason", self.reason.as_str())
    }
}

/// Everything a deleted tenant held was removed, its audit trail kept.
///
/// The tenant's teardown raises it once its last step is done.
#[derive(Debug)]
pub(crate) struct TenantTornDown {
    /// When the last step was done.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantTornDown => crate::types::event_type::TenantEvent::TornDown,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A step of a deleted tenant's teardown failed for good, so the teardown
/// stopped.
///
/// The tenant's teardown raises it, naming the step and why it failed, for
/// the operators to act on. What the steps before it removed stays removed.
#[derive(Debug)]
pub struct TeardownFailed {
    /// The step that failed, as the teardown names it.
    pub(crate) step: &'static str,
    /// Why it failed, as the step reported it.
    pub(crate) reason: UntrustedText,
    /// When the failure occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TeardownFailed => crate::types::event_type::TenantEvent::TeardownFailed,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("step", self.step)
            .field("reason", self.reason.as_str())
    }
}

/// A tenant was permanently deleted.
///
/// The tenant's teardown begins on it, and removes everything the tenant
/// held.
#[derive(Debug)]
pub(crate) struct TenantDeleted {
    /// When the deletion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDeleted => crate::types::event_type::TenantEvent::Deleted,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// The platform deleted an archived tenant before its grace had run.
///
/// It goes out beside [`TenantDeleted`], which the teardown worker reads.
/// This one says why the grace was cut short and carries the platform's
/// note, so an early wipe never reads like an ordinary deletion in the
/// audit trail.
#[derive(Debug)]
pub(crate) struct TenantDeletedEarly {
    /// Why the platform did not wait, with its note.
    pub(crate) reason: EarlyDeletion,
    /// When the deletion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantDeletedEarly => crate::types::event_type::TenantEvent::DeletedEarly,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("reason", self.reason.as_str())
            .field("note", self.reason.note().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::config::{DisplayNameLimits, SlugLimits};
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;
    use crate::types::Text;

    /// The two halves of a recorded change: what it was, and what it became.
    fn expect_change(payload: &EventData, key: &str) -> (Option<String>, Option<String>) {
        let Some(FieldValue::Change(change)) = payload.value(key) else {
            panic!("expected a change at {key}");
        };
        (
            change.from().map(str::to_owned),
            change.to().map(str::to_owned),
        )
    }

    fn acme_provisioned() -> TenantProvisioned {
        TenantProvisioned {
            tenant_id: TenantId::new(),
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            display_name: DisplayName::new("Acme Corp", &DisplayNameLimits::default()).unwrap(),
            occurred_at: crate::shared::clock::now(),
        }
    }

    /// Acme Corp is provisioned. The event goes out as
    /// `tenant.provisioned`, the name the worker listens for.
    #[test]
    fn provisioned_event_has_correct_type() {
        let event = acme_provisioned();

        assert_eq!(event.event_type().as_str(), "tenant.provisioned");
    }

    /// Acme Corp is provisioned with slug `acme`. The payload carries both
    /// the slug and the display name, and links the tenant.
    #[test]
    fn provisioned_event_payload_contains_all_fields() {
        let event = acme_provisioned();

        let payload = event.payload();
        assert_eq!(payload.get("slug"), Some("acme"));
        assert_eq!(payload.get("display_name"), Some("Acme Corp"));
        let Some(FieldValue::Reference(tenant)) = payload.value("tenant") else {
            panic!("the tenant is not referenced");
        };
        assert_eq!(tenant.id(), event.tenant_id.to_string());
    }

    /// Acme is suspended. The event goes out as `tenant.status_changed` and
    /// records the move from `active` to `suspended`.
    #[test]
    fn status_changed_event_captures_transition() {
        let event = TenantStatusChanged {
            tenant_id: TenantId::new(),
            tenant_label: EventLabel::of("Acme Corp"),
            from: TenantStatus::Active,
            to: TenantStatus::Suspended,
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(event.event_type().as_str(), "tenant.status_changed");

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("status") else {
            panic!("status must be recorded as a change");
        };
        assert_eq!(change.from(), Some("active"));
        assert_eq!(change.to(), Some("suspended"));
    }

    /// Acme Corp is renamed to Acme Industries. The event records the old
    /// and the new name as one change.
    #[test]
    fn renamed_event_captures_both_names() {
        let event = TenantRenamed {
            old_name: DisplayName::new("Acme Corp", &DisplayNameLimits::default()).unwrap(),
            new_name: DisplayName::new("Acme Industries", &DisplayNameLimits::default()).unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("name") else {
            panic!("name must be recorded as a change");
        };
        assert_eq!(change.from(), Some("Acme Corp"));
        assert_eq!(change.to(), Some("Acme Industries"));
    }

    /// Acme's contact email change records the previous and replacement mailbox.
    #[test]
    fn the_settings_changes_record_both_the_old_and_the_new_value() {
        let email = TenantContactEmailChanged {
            old_email: Email::new("ops@acme.com").unwrap(),
            new_email: Email::new("security@acme.com").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(
            expect_change(&email.payload(), "email"),
            (
                Some("ops@acme.com".to_owned()),
                Some("security@acme.com".to_owned())
            )
        );
    }

    /// Moving from UTC to Berlin records both timezones in the audit change.
    #[test]
    fn timezone_changes_record_the_previous_and_replacement_zone() {
        let timezone = TenantTimezoneChanged {
            old_timezone: Timezone::new("UTC").unwrap(),
            new_timezone: Timezone::new("Europe/Berlin").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };
        assert_eq!(
            expect_change(&timezone.payload(), "timezone"),
            (Some("UTC".to_owned()), Some("Europe/Berlin".to_owned()))
        );
    }

    /// Switching from English to German records both locale identifiers.
    #[test]
    fn locale_changes_record_the_previous_and_replacement_language() {
        let locale = TenantLocaleChanged {
            old_locale: Locale::new("en-US").unwrap(),
            new_locale: Locale::new("de-DE").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };
        assert_eq!(
            expect_change(&locale.payload(), "locale"),
            (Some("en-US".to_owned()), Some("de-DE".to_owned()))
        );
    }

    /// Acme forbids impersonation and cuts audit retention from 365 to 90
    /// days. The event goes out as `tenant.compliance_changed` and records
    /// all three settings before and after.
    #[test]
    fn a_compliance_change_records_each_setting_before_and_after() {
        let limits = crate::domains::tenant::compliance_limits::ComplianceLimits::default();
        let before = CompliancePosture::default_from(&limits);
        let after = CompliancePosture::new(
            crate::domains::tenant::compliance::Residency::Anywhere,
            90,
            crate::domains::tenant::compliance::OperatorImpersonation::Allowed,
            &limits,
        )
        .unwrap();

        let event = TenantComplianceChanged {
            before,
            after,
            occurred_at: crate::shared::clock::now(),
        };
        let payload = event.payload();

        assert_eq!(event.event_type().as_str(), "tenant.compliance_changed");
        assert_eq!(
            expect_change(&payload, "data_residency"),
            (Some("anywhere".to_owned()), Some("anywhere".to_owned()))
        );
        assert_eq!(
            expect_change(&payload, "audit_retention_days"),
            (Some("365".to_owned()), Some("90".to_owned()))
        );
        assert_eq!(
            expect_change(&payload, "operator_impersonation"),
            (Some("forbidden".to_owned()), Some("allowed".to_owned()))
        );
    }

    /// The platform wipes a tenant sending phishing mail on the day it was
    /// archived. The event goes out as `tenant.deleted_early` and records
    /// the reason and the platform's note.
    #[test]
    fn an_early_deletion_records_its_reason_and_note() {
        let event = TenantDeletedEarly {
            reason: EarlyDeletion::Abuse(Text::new("note", "phishing pages").unwrap()),
            occurred_at: crate::shared::clock::now(),
        };
        let payload = event.payload();

        assert_eq!(event.event_type().as_str(), "tenant.deleted_early");
        assert_eq!(payload.get("reason"), Some("abuse"));
        assert_eq!(payload.get("note"), Some("phishing pages"));
    }
}
