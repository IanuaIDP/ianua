//! How a tenant moves through its life, and who may move it.
//!
//! The platform finishes provisioning. A member of the tenant's
//! organization, or the platform, suspends, archives, restores and deletes
//! it. A tenant the platform holds comes back only through the platform. An
//! archived tenant waits [`ARCHIVE_GRACE`] before it may be deleted.
//!
//! Every move raises `tenant.status_changed` with the status it left and
//! the one it reached. A deletion raises `tenant.deleted` after it, which
//! the teardown worker reads.

use time::OffsetDateTime;

use crate::domains::tenant::control::{LifecycleStep, Steward, ensure_may_take};
use crate::domains::tenant::events::lifecycle::{
    TenantDeleted, TenantDeletedEarly, TenantStatusChanged,
};
use crate::domains::tenant::lifecycle::Tenant;
use crate::domains::tenant::status::{
    ARCHIVE_GRACE, Archival, InvalidTenantTransition, PlatformHold, TenantStatus,
};
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ActedBy, Text};

/// Why the platform deletes an archived tenant before its grace has run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EarlyDeletion {
    /// The tenant was used for abuse, such as phishing, with this note.
    Abuse(Text),
    /// A court or regulator ordered it, with this note naming the order.
    LegalOrder(Text),
}

impl EarlyDeletion {
    /// The stable name the audit record carries.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Abuse(_) => "abuse",
            Self::LegalOrder(_) => "legal_order",
        }
    }

    /// The note saying what happened or which order it was.
    #[must_use]
    pub fn note(&self) -> &Text {
        match self {
            Self::Abuse(note) | Self::LegalOrder(note) => note,
        }
    }
}

impl Tenant {
    /// Marks provisioning as complete and makes the tenant operational.
    ///
    /// Only the platform does this. It is the one that knows the database,
    /// keys and default roles exist. Works only from `Provisioning`. A
    /// suspended tenant comes back through [`reactivate`](Self::reactivate).
    /// Raises `tenant.status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a member of the organization asks.
    /// - [`DomainError::InvalidTransition`] when the tenant is not
    ///   `Provisioning`.
    pub fn activate(&mut self, by: Steward<'_>) -> Result<TenantStatus, DomainError> {
        if let ActedBy::By(_) = by {
            return Err(DomainError::forbidden(message!(
                "tenant-only-the-platform-finishes-provisioning-a",
                "only the platform finishes provisioning a tenant"
            )));
        }
        self.ensure_in(TenantStatus::Provisioning, TenantStatus::Active)?;
        self.move_to(TenantStatus::Active)
            .map_err(DomainError::from)
    }

    /// Freezes the tenant. Nothing done in its name is served until it is
    /// reactivated, see [`TenantStatus::is_open`].
    ///
    /// When the platform suspends it, the platform holds it, and only the
    /// platform brings it back. Raises `tenant.status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the member may not suspend it.
    /// - [`DomainError::InvalidTransition`] unless the tenant is `Active`.
    pub fn suspend(&mut self, by: Steward<'_>) -> Result<TenantStatus, DomainError> {
        ensure_may_take(by, &self.organization_id, LifecycleStep::Suspend)?;
        let status = self.move_to(TenantStatus::Suspended)?;
        self.hold = hold_set_by(by);
        Ok(status)
    }

    /// Brings a suspended tenant back to `Active`.
    ///
    /// Works only from `Suspended`. A new tenant becomes active through
    /// [`activate`](Self::activate), an archived one through
    /// [`restore`](Self::restore). Raises `tenant.status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the member may not reactivate it,
    ///   or the platform holds it.
    /// - [`DomainError::InvalidTransition`] when the tenant is not suspended.
    pub fn reactivate(&mut self, by: Steward<'_>) -> Result<TenantStatus, DomainError> {
        self.ensure_may_bring_back(by, LifecycleStep::Reactivate)?;
        self.ensure_in(TenantStatus::Suspended, TenantStatus::Active)?;
        let status = self.move_to(TenantStatus::Active)?;
        self.hold = PlatformHold::Free;
        Ok(status)
    }

    /// Soft-deletes the tenant. Nothing done in its name is served from now
    /// on. It may be restored until it is deleted, and deleted once
    /// [`ARCHIVE_GRACE`] has passed.
    ///
    /// When the platform archives it, the platform holds it. A tenant the
    /// platform already holds stays held. Raises `tenant.status_changed`.
    ///
    /// A tenant still provisioning is archived by the platform only, which
    /// stops its setup: the step that would activate it is then refused.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the member may not archive it, or
    ///   it is still provisioning.
    /// - [`DomainError::InvalidTransition`] unless the tenant is
    ///   `Provisioning`, `Active` or `Suspended`.
    pub fn archive(&mut self, by: Steward<'_>) -> Result<TenantStatus, DomainError> {
        ensure_may_take(by, &self.organization_id, LifecycleStep::Archive)?;
        self.ensure_setup_stopped_by_platform(by)?;
        let status = self.move_to(TenantStatus::Archived)?;
        self.archival = Archival::Since(self.updated_at);
        if let ActedBy::Platform = by {
            self.hold = PlatformHold::Held;
        }
        Ok(status)
    }

    /// Brings an archived tenant back to `Active`, before it is deleted.
    /// Raises `tenant.status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the member may not restore it, or
    ///   the platform holds it.
    /// - [`DomainError::InvalidTransition`] when the tenant is not archived.
    pub fn restore(&mut self, by: Steward<'_>) -> Result<TenantStatus, DomainError> {
        self.ensure_may_bring_back(by, LifecycleStep::Restore)?;
        self.ensure_in(TenantStatus::Archived, TenantStatus::Active)?;
        let status = self.move_to(TenantStatus::Active)?;
        self.archival = Archival::NotArchived;
        self.hold = PlatformHold::Free;
        Ok(status)
    }

    /// Marks the tenant deleted. This cannot be undone. Raises
    /// `tenant.status_changed`, then `tenant.deleted`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the member may not delete it.
    /// - [`DomainError::InvalidTransition`] when the tenant is not archived.
    /// - [`DomainError::Conflict`] when [`ARCHIVE_GRACE`] has not passed
    ///   since it was archived.
    pub fn delete(&mut self, by: Steward<'_>) -> Result<TenantStatus, DomainError> {
        ensure_may_take(by, &self.organization_id, LifecycleStep::Delete)?;
        self.ensure_in(TenantStatus::Archived, TenantStatus::Deleted)?;
        self.ensure_grace_over(crate::shared::clock::now())?;
        let status = self.move_to(TenantStatus::Deleted)?;
        self.raise_deleted();
        Ok(status)
    }

    /// Deletes an archived tenant before its grace has run, for the
    /// platform, with a recorded `reason`.
    ///
    /// The grace protects an owner from their own mistake. It does not
    /// protect a tenant sending phishing mail, or one a court ordered
    /// removed. Only the platform may cut it short, and the reason goes on
    /// the record. A member of the organization always waits.
    ///
    /// Raises `tenant.status_changed`, `tenant.deleted`, then
    /// `tenant.deleted_early` with the reason and note, so an early wipe
    /// never reads like an ordinary deletion.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a member of the organization asks.
    /// - [`DomainError::InvalidTransition`] when the tenant is not archived.
    pub fn delete_early(
        &mut self,
        by: Steward<'_>,
        reason: EarlyDeletion,
    ) -> Result<TenantStatus, DomainError> {
        if let ActedBy::By(_) = by {
            return Err(DomainError::forbidden(message!(
                "tenant-only-the-platform-deletes-a-tenant",
                format!(
                    "only the platform deletes a tenant early, as for {}",
                    reason.as_str()
                )
            )));
        }
        self.ensure_in(TenantStatus::Archived, TenantStatus::Deleted)?;
        let status = self.move_to(TenantStatus::Deleted)?;
        self.raise_deleted();
        self.raise(TenantDeletedEarly {
            reason,
            occurred_at: self.updated_at,
        });
        Ok(status)
    }

    /// Raises the deletion the teardown worker reads.
    fn raise_deleted(&mut self) {
        self.raise(TenantDeleted {
            occurred_at: self.updated_at,
        });
    }

    /// The first moment the tenant may be deleted, while it is archived.
    #[must_use]
    pub fn deletable_from(&self) -> Option<OffsetDateTime> {
        self.archival.deletable_from()
    }

    /// Refuses to bring the tenant back for a member who may not take
    /// `step`, or while the platform holds it.
    fn ensure_may_bring_back(
        &self,
        by: Steward<'_>,
        step: LifecycleStep,
    ) -> Result<(), DomainError> {
        ensure_may_take(by, &self.organization_id, step)?;
        match (by, self.hold) {
            (ActedBy::By(_), PlatformHold::Held) => Err(DomainError::forbidden(message!(
                "tenant-the-platform-holds-this-tenant-so",
                "the platform holds this tenant, so only the platform brings it back"
            ))),
            (ActedBy::Platform, PlatformHold::Held | PlatformHold::Free)
            | (ActedBy::By(_), PlatformHold::Free) => Ok(()),
        }
    }

    /// Refuses a member archiving a tenant still provisioning.
    ///
    /// The platform runs the setup, so only the platform stops it. Without
    /// this, Acme's owner archives a tenant whose database is half made, and
    /// restores it as active before its keys and roles exist.
    fn ensure_setup_stopped_by_platform(&self, by: Steward<'_>) -> Result<(), DomainError> {
        match (by, self.status) {
            (ActedBy::By(_), TenantStatus::Provisioning) => Err(DomainError::forbidden(message!(
                "tenant-only-the-platform-stops-the-setup",
                "only the platform stops the setup of a tenant still provisioning"
            ))),
            _ => Ok(()),
        }
    }

    /// Refuses a deletion before the grace that follows archiving is over.
    fn ensure_grace_over(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        let Some(from) = self.deletable_from() else {
            return Err(DomainError::conflict(message!(
                "tenant-the-tenant-was-never-archived",
                "the tenant was never archived"
            )));
        };
        if now < from {
            let from = day_in_words(from);
            return Err(DomainError::conflict(message!(
                "tenant-an-archived-tenant-may-be-deleted",
                format!(
                    "an archived tenant may be deleted from {from} on, {} days after it was archived",
                    ARCHIVE_GRACE.whole_days()
                )
            )));
        }
        Ok(())
    }

    /// Refuses a move to `to` unless the tenant is in `from`.
    fn ensure_in(
        &self,
        from: TenantStatus,
        to: TenantStatus,
    ) -> Result<(), InvalidTenantTransition> {
        if self.status != from {
            return Err(InvalidTenantTransition {
                from: self.status,
                to,
            });
        }
        Ok(())
    }

    /// Moves the tenant to `target` when [`TenantStatus`] allows it, and
    /// raises the move.
    fn move_to(&mut self, target: TenantStatus) -> Result<TenantStatus, InvalidTenantTransition> {
        let new_status = self.status.try_transition(target)?;
        let from = std::mem::replace(&mut self.status, new_status);
        self.touch();
        self.raise(TenantStatusChanged {
            tenant_id: self.id,
            tenant_label: self.label(),
            from,
            to: new_status,
            occurred_at: self.updated_at,
        });
        Ok(new_status)
    }
}

/// `at` as a person reads a date in a refusal, `9 December 2026`.
fn day_in_words(at: OffsetDateTime) -> String {
    format!("{} {} {}", at.day(), at.month(), at.year())
}

/// The hold a suspension leaves: the platform's own suspension is one only
/// it lifts.
fn hold_set_by(by: Steward<'_>) -> PlatformHold {
    match by {
        ActedBy::Platform => PlatformHold::Held,
        ActedBy::By(_) => PlatformHold::Free,
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::tenant::fixtures::{Member, active, provisioned};
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEvent;
    use crate::shared::events::raised::RaisesComplete;
    use crate::test_support::events::raised_complete_names;

    const EVERY_STEP: &[LifecycleStep] = &[
        LifecycleStep::Suspend,
        LifecycleStep::Reactivate,
        LifecycleStep::Archive,
        LifecycleStep::Restore,
        LifecycleStep::Delete,
    ];

    fn archived_by_owner() -> (Tenant, OffsetDateTime) {
        let mut tenant = active();
        let owner = Member::of(&tenant, EVERY_STEP);
        tenant.archive(ActedBy::By(&owner)).unwrap();
        let archived_at = tenant.updated_at();
        (tenant, archived_at)
    }

    /// The platform activates a tenant, an owner suspends, reactivates and
    /// archives it, and once the grace has passed deletes it. Each step lands
    /// in the expected status.
    #[test]
    fn full_lifecycle_provisioning_to_deleted() {
        let mut tenant = provisioned();
        let owner = Member::of(&tenant, EVERY_STEP);

        tenant.activate(ActedBy::Platform).unwrap();
        tenant.suspend(ActedBy::By(&owner)).unwrap();
        assert_eq!(tenant.status(), TenantStatus::Suspended);
        tenant.reactivate(ActedBy::By(&owner)).unwrap();
        tenant.archive(ActedBy::By(&owner)).unwrap();
        assert_eq!(tenant.status(), TenantStatus::Archived);

        let _later = crate::shared::clock::freeze(tenant.updated_at() + ARCHIVE_GRACE);
        tenant.delete(ActedBy::By(&owner)).unwrap();

        assert_eq!(tenant.status(), TenantStatus::Deleted);
    }

    /// An organization member cannot activate a provisioning tenant; it stays
    /// in provisioning until the platform finishes setup.
    #[test]
    fn only_the_platform_finishes_provisioning() {
        let mut tenant = provisioned();
        let owner = Member::of(&tenant, EVERY_STEP);

        assert!(matches!(
            tenant.activate(ActedBy::By(&owner)),
            Err(DomainError::Forbidden(_))
        ));
        assert_eq!(tenant.status(), TenantStatus::Provisioning);
    }

    /// Acme closes while its tenant is still being set up. The platform
    /// archives it and holds it, and the setup step that would activate it
    /// later is refused.
    #[test]
    fn the_platform_stops_a_setup_by_archiving() {
        let mut tenant = provisioned();

        tenant.archive(ActedBy::Platform).unwrap();

        assert_eq!(tenant.status(), TenantStatus::Archived);
        assert_eq!(tenant.hold(), PlatformHold::Held);
        assert!(tenant.activate(ActedBy::Platform).is_err());
    }

    /// An organization member cannot archive a tenant while setup is underway.
    /// The tenant remains in provisioning after the refusal.
    #[test]
    fn a_member_does_not_archive_a_tenant_still_provisioning() {
        let mut tenant = provisioned();
        let owner = Member::of(&tenant, EVERY_STEP);

        let refused = tenant.archive(ActedBy::By(&owner));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(tenant.status(), TenantStatus::Provisioning);
    }

    /// A member without suspension rights and a member of another organization
    /// cannot suspend the tenant, which remains active.
    #[test]
    fn suspending_needs_a_member_of_the_organization_with_the_right() {
        let mut tenant = active();
        let bob = Member::of(&tenant, &[]);
        let eve = Member::elsewhere();

        assert!(matches!(
            tenant.suspend(ActedBy::By(&bob)),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            tenant.suspend(ActedBy::By(&eve)),
            Err(DomainError::Forbidden(_))
        ));
        assert_eq!(tenant.status(), TenantStatus::Active);
    }

    /// An organization member cannot lift a platform suspension. The platform
    /// can reactivate the tenant and clear its hold.
    #[test]
    fn a_suspension_the_platform_made_is_lifted_only_by_the_platform() {
        let mut tenant = active();
        let owner = Member::of(&tenant, EVERY_STEP);
        tenant.suspend(ActedBy::Platform).unwrap();

        let by_owner = tenant.reactivate(ActedBy::By(&owner));
        let by_platform = tenant.reactivate(ActedBy::Platform);

        assert!(matches!(by_owner, Err(DomainError::Forbidden(_))));
        assert_eq!(by_platform.unwrap(), TenantStatus::Active);
        assert_eq!(tenant.hold(), PlatformHold::Free);
    }

    /// An organization member can archive a platform-suspended tenant, but its
    /// hold remains and prevents that member from restoring it.
    #[test]
    fn archiving_does_not_wash_away_the_platforms_hold() {
        let mut tenant = active();
        let owner = Member::of(&tenant, EVERY_STEP);
        tenant.suspend(ActedBy::Platform).unwrap();

        tenant.archive(ActedBy::By(&owner)).unwrap();

        assert_eq!(tenant.hold(), PlatformHold::Held);
        assert!(matches!(
            tenant.restore(ActedBy::By(&owner)),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// An owner suspends Acme's tenant and reactivates it later. Both are
    /// allowed, and no hold is left.
    #[test]
    fn an_owner_lifts_their_own_suspension() {
        let mut tenant = active();
        let owner = Member::of(&tenant, EVERY_STEP);

        tenant.suspend(ActedBy::By(&owner)).unwrap();
        assert_eq!(tenant.hold(), PlatformHold::Free);

        assert_eq!(
            tenant.reactivate(ActedBy::By(&owner)).unwrap(),
            TenantStatus::Active
        );
    }

    /// Deletion 29 days after archival is refused. The tenant stays archived
    /// and retains the deletion date at the end of its grace period.
    #[test]
    fn an_archived_tenant_cannot_be_deleted_before_the_grace_ends() {
        let (mut tenant, archived_at) = archived_by_owner();
        let owner = Member::of(&tenant, EVERY_STEP);

        let _soon = crate::shared::clock::freeze(archived_at + Duration::days(29));
        let refused = tenant.delete(ActedBy::By(&owner));

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(tenant.status(), TenantStatus::Archived);
        assert_eq!(tenant.deletable_from(), Some(archived_at + ARCHIVE_GRACE));
    }

    /// Ann tries to delete too early and is told the day she may, written
    /// as a date and not as a machine timestamp.
    #[test]
    fn deleting_too_early_names_the_day_in_words() {
        let (mut tenant, archived_at) = archived_by_owner();
        let owner = Member::of(&tenant, EVERY_STEP);
        let from = archived_at + ARCHIVE_GRACE;

        let _soon = crate::shared::clock::freeze(archived_at + Duration::days(1));
        let refused = tenant.delete(ActedBy::By(&owner)).unwrap_err().to_string();

        assert!(
            refused.contains(&format!("{} {} {}", from.day(), from.month(), from.year())),
            "the refusal names the day: {refused}"
        );
        assert!(!refused.contains("+00"), "no raw timestamp: {refused}");
    }

    /// Acme archived its tenant by mistake and restores it the next day. It
    /// is active again, and its archive time is cleared.
    #[test]
    fn an_owner_restores_an_archived_tenant() {
        let (mut tenant, _) = archived_by_owner();
        let owner = Member::of(&tenant, EVERY_STEP);

        assert_eq!(
            tenant.restore(ActedBy::By(&owner)).unwrap(),
            TenantStatus::Active
        );
        assert_eq!(tenant.archival(), Archival::NotArchived);
        assert_eq!(tenant.deletable_from(), None);
    }

    /// The platform archives a tenant whose organization closed. The owner
    /// cannot restore it. The platform can.
    #[test]
    fn a_tenant_the_platform_archived_is_restored_only_by_the_platform() {
        let mut tenant = active();
        let owner = Member::of(&tenant, EVERY_STEP);
        tenant.archive(ActedBy::Platform).unwrap();

        assert!(matches!(
            tenant.restore(ActedBy::By(&owner)),
            Err(DomainError::Forbidden(_))
        ));
        assert!(tenant.restore(ActedBy::Platform).is_ok());
    }

    /// An active tenant is deleted without being archived first. It is
    /// refused, so data always passes through archive before it is wiped.
    #[test]
    fn cannot_delete_without_archiving() {
        let mut tenant = active();
        assert!(matches!(
            tenant.delete(ActedBy::Platform),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// A tenant still provisioning is suspended. It is refused.
    #[test]
    fn cannot_suspend_while_provisioning() {
        let mut tenant = provisioned();
        assert!(tenant.suspend(ActedBy::Platform).is_err());
    }

    /// An active tenant is activated a second time. It is refused.
    #[test]
    fn cannot_activate_while_active() {
        let mut tenant = active();
        assert!(tenant.activate(ActedBy::Platform).is_err());
    }

    /// A suspended tenant is brought back with `activate`. It is refused,
    /// since only `reactivate` ends a suspension.
    #[test]
    fn cannot_activate_while_suspended() {
        let mut tenant = active();
        tenant.suspend(ActedBy::Platform).unwrap();
        assert!(tenant.activate(ActedBy::Platform).is_err());
    }

    /// A tenant still provisioning, or active and never suspended, is
    /// reactivated. Both are refused.
    #[test]
    fn cannot_reactivate_unless_suspended() {
        assert!(provisioned().reactivate(ActedBy::Platform).is_err());
        assert!(active().reactivate(ActedBy::Platform).is_err());
    }

    /// An archived tenant is reactivated. It is refused, since an archived
    /// tenant comes back only through `restore`.
    #[test]
    fn cannot_reactivate_while_archived() {
        let (mut tenant, _) = archived_by_owner();
        assert!(tenant.reactivate(ActedBy::Platform).is_err());
    }

    /// A suspended tenant is restored. It is refused, since only an archived
    /// tenant is restored.
    #[test]
    fn cannot_restore_unless_archived() {
        let mut tenant = active();
        tenant.suspend(ActedBy::Platform).unwrap();
        assert!(matches!(
            tenant.restore(ActedBy::Platform),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// An organization member cannot delete an archived tenant early, while
    /// the platform can do so with an abuse reason.
    #[test]
    fn only_the_platform_deletes_before_the_grace_has_run() {
        let (mut tenant, _) = archived_by_owner();
        let owner = Member::of(&tenant, EVERY_STEP);

        let by_owner = tenant.delete_early(ActedBy::By(&owner), phishing());
        let by_platform = tenant.delete_early(ActedBy::Platform, phishing());

        assert!(matches!(by_owner, Err(DomainError::Forbidden(_))));
        assert_eq!(by_platform.unwrap(), TenantStatus::Deleted);
    }

    /// Early deletion raises the status change, deletion and early-deletion
    /// events in order, recording the tenant, abuse reason and explanatory note.
    #[test]
    fn an_early_deletion_raises_the_record_of_why() {
        let (mut tenant, _) = archived_by_owner();
        raised_complete_names(&mut tenant);

        tenant.delete_early(ActedBy::Platform, phishing()).unwrap();

        let events = tenant.take_events();
        assert_eq!(
            names(&events),
            [
                "tenant.status_changed",
                "tenant.deleted",
                "tenant.deleted_early"
            ]
        );
        assert_eq!(events[2].tenant_id(), Some(tenant.id()));
        assert_eq!(events[2].payload().get("reason"), Some("abuse"));
        assert_eq!(events[2].payload().get("note"), Some("phishing pages"));
    }

    /// The platform activates Acme's tenant, and its owner suspends it.
    /// Each move raises `tenant.status_changed` naming the tenant and the
    /// status it left and reached.
    #[test]
    fn each_move_raises_tenant_status_changed() {
        let mut tenant = provisioned();
        let owner = Member::of(&tenant, EVERY_STEP);
        raised_complete_names(&mut tenant);

        tenant.activate(ActedBy::Platform).unwrap();
        tenant.suspend(ActedBy::By(&owner)).unwrap();

        let events = tenant.take_events();
        assert_eq!(
            names(&events),
            ["tenant.status_changed", "tenant.status_changed"]
        );
        assert_eq!(status_change(&events[0]), moved("provisioning", "active"));
        assert_eq!(status_change(&events[1]), moved("active", "suspended"));
        assert_eq!(events[1].tenant_id(), Some(tenant.id()));
    }

    /// Acme's owner reactivates, archives, restores, archives again and,
    /// once the grace has passed, deletes the tenant. Each move is raised,
    /// and the deletion is raised after it.
    #[test]
    fn bringing_back_archiving_and_deleting_raise_their_moves() {
        let mut tenant = active();
        let owner = Member::of(&tenant, EVERY_STEP);
        tenant.suspend(ActedBy::By(&owner)).unwrap();
        raised_complete_names(&mut tenant);

        tenant.reactivate(ActedBy::By(&owner)).unwrap();
        tenant.archive(ActedBy::By(&owner)).unwrap();
        tenant.restore(ActedBy::By(&owner)).unwrap();
        tenant.archive(ActedBy::By(&owner)).unwrap();
        let _later = crate::shared::clock::freeze(tenant.updated_at() + ARCHIVE_GRACE);
        tenant.delete(ActedBy::By(&owner)).unwrap();

        let events = tenant.take_events();
        assert_eq!(names(&events).len(), 6);
        assert_eq!(status_change(&events[3]), moved("active", "archived"));
        assert_eq!(status_change(&events[4]), moved("archived", "deleted"));
        assert_eq!(names(&events)[5], "tenant.deleted");
    }

    /// Suspending without the required right and deleting before the archive
    /// grace expires are both refused without raising events.
    #[test]
    fn a_refused_move_raises_nothing() {
        let (mut tenant, _) = archived_by_owner();
        let bob = Member::of(&tenant, &[]);
        let owner = Member::of(&tenant, EVERY_STEP);
        raised_complete_names(&mut tenant);

        let suspended = tenant.suspend(ActedBy::By(&bob));
        let deleted = tenant.delete(ActedBy::By(&owner));

        assert!(suspended.is_err());
        assert!(deleted.is_err());
        assert!(tenant.take_events().is_empty());
    }

    fn names(events: &[DomainEvent]) -> Vec<String> {
        events
            .iter()
            .map(|event| event.event_type().to_string())
            .collect()
    }

    fn status_change(event: &DomainEvent) -> (String, String) {
        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("status") else {
            panic!("the status is not recorded as a change");
        };
        (
            change.from().unwrap().to_owned(),
            change.to().unwrap().to_owned(),
        )
    }

    fn moved(from: &str, to: &str) -> (String, String) {
        (from.to_owned(), to.to_owned())
    }

    fn phishing() -> EarlyDeletion {
        EarlyDeletion::Abuse(Text::new("note", "phishing pages").unwrap())
    }
}
