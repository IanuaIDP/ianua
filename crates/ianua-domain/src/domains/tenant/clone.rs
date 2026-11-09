//! Copying one tenant's setup into another tenant of the same organization.
//!
//! Ann runs Acme's production tenant and wants a staging tenant that signs
//! people in the same way. She provisions the staging tenant, then starts a
//! clone from production into it, naming the parts to copy. A worker copies
//! each part and records it here; once every part is copied the clone is
//! complete. People, sessions, signing keys and secrets are never copied:
//! a clone gives the new tenant the same shape, never the same users or
//! the same keys.

use time::OffsetDateTime;

use crate::domains::tenant::control::{LifecycleStep, Steward, ensure_may_take};
use crate::domains::tenant::events::clone::{
    TenantCloneCompleted, TenantCloneFailed, TenantCloneStarted,
};
use crate::domains::tenant::lifecycle::Tenant;
use crate::domains::tenant::status::TenantStatus;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete, TenantEventBody};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{EventLabel, OrganizationId, TenantCloneId, TenantId};

/// One part of a tenant's setup a clone copies.
///
/// There is no part for users, sessions, signing keys or secrets, so no
/// clone can carry them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClonePart {
    /// Sign-in settings, mutual TLS, timezone and locale.
    Settings,
    /// The login page's look and the email templates.
    Branding,
    /// Roles, groups and access policies, with the resource types their
    /// permissions name, separation of duty, clearance and the longest
    /// access a person may ask for, without who holds any of them.
    RolesAndPolicies,
    /// Proxy routes, the services they forward to, the pipelines they run
    /// and the classification rule set those pipelines read.
    Routes,
    /// OAuth applications, without their secrets.
    OAuthApplications,
}

impl ClonePart {
    /// Every part, in the order a worker copies them.
    pub const ALL: [Self; 5] = [
        Self::Settings,
        Self::Branding,
        Self::RolesAndPolicies,
        Self::Routes,
        Self::OAuthApplications,
    ];

    /// The stable name storage and the API use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Settings => "settings",
            Self::Branding => "branding",
            Self::RolesAndPolicies => "roles_and_policies",
            Self::Routes => "routes",
            Self::OAuthApplications => "oauth_applications",
        }
    }

    /// The part stored under `value`, or `None` for a name the domain does
    /// not define, which storage reports as corrupt.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|part| part.as_str() == value)
    }
}

/// Why a clone stopped before it finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneFailure {
    /// The source tenant was archived or deleted while it was copied.
    SourceGone,
    /// The target tenant was closed while it was filled.
    TargetGone,
    /// A part could not be copied.
    CopyFailed,
}

impl CloneFailure {
    /// The stable name storage and records use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceGone => "source_gone",
            Self::TargetGone => "target_gone",
            Self::CopyFailed => "copy_failed",
        }
    }
}

/// Where a clone is. It moves from `Copying` to `Completed` or `Failed`,
/// and no further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneState {
    /// Parts are being copied.
    Copying,
    /// Every part was copied.
    Completed {
        /// When the last part was copied.
        at: OffsetDateTime,
    },
    /// It stopped before every part was copied.
    Failed {
        /// When it stopped.
        at: OffsetDateTime,
        /// Why.
        reason: CloneFailure,
    },
}

impl CloneState {
    /// When it ended, while it has.
    fn ended_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Copying => None,
            Self::Completed { at } | Self::Failed { at, .. } => Some(at),
        }
    }
}

/// A [`TenantClone`] as storage holds it, read back through
/// [`TenantClone::reconstitute`].
pub struct TenantCloneRow {
    /// The clone.
    pub id: TenantCloneId,
    /// The organization both tenants belong to.
    pub organization_id: OrganizationId,
    /// The tenant copied from.
    pub source: TenantId,
    /// The tenant filled.
    pub target: TenantId,
    /// What is copied.
    pub parts: Vec<ClonePart>,
    /// What was copied so far.
    pub copied: Vec<ClonePart>,
    /// Where it is.
    pub state: CloneState,
    /// When it started.
    pub started_at: OffsetDateTime,
}

/// A copy of one tenant's setup into another of the same organization.
#[derive(Debug)]
pub struct TenantClone {
    id: TenantCloneId,
    organization_id: OrganizationId,
    source: TenantId,
    target: TenantId,
    parts: Vec<ClonePart>,
    copied: Vec<ClonePart>,
    state: CloneState,
    started_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl TenantClone {
    /// Starts copying `parts` of `source` into `target`, as `by` decides.
    /// Raises `tenant.clone_started`, filed under `target`.
    ///
    /// A clone gives `target` the sign-in settings, roles and routes of
    /// `source`, so it needs the right to make tenants in their
    /// organization. Sam may only suspend Acme's tenants. Without the check
    /// he copies production's routes into a tenant of his own.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not provision tenants in
    ///   `source`'s organization.
    /// - [`DomainError::Forbidden`] when `target` belongs to another
    ///   organization.
    /// - [`DomainError::Validation`] when `source` and `target` are the same
    ///   tenant, or `parts` is empty or names a part twice.
    /// - [`DomainError::Conflict`] when `source` is archived or deleted, or
    ///   `target` is not provisioning or active.
    pub fn start(
        parts: Vec<ClonePart>,
        source: &Tenant,
        target: &Tenant,
        by: Steward<'_>,
    ) -> Result<Self, DomainError> {
        ensure_may_take(by, source.organization_id(), LifecycleStep::Provision)?;
        ensure_pair(source, target)?;
        ensure_parts(&parts)?;
        let now = crate::shared::clock::now();
        let mut clone = Self {
            id: TenantCloneId::new(),
            organization_id: *source.organization_id(),
            source: *source.id(),
            target: *target.id(),
            parts,
            copied: Vec::new(),
            state: CloneState::Copying,
            started_at: now,
            raised: RaisedEvents::default(),
        };
        clone.raise(TenantCloneStarted {
            clone_id: clone.id,
            source_id: clone.source,
            source_label: EventLabel::of(source.display_name().as_str()),
            parts: clone.parts.clone(),
            occurred_at: now,
        });
        Ok(clone)
    }

    /// Rebuilds a clone from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row copies a tenant into
    ///   itself, names no part or one twice, holds a copied part it never
    ///   asked for, is complete with a part missing, or ended before it
    ///   started.
    pub fn reconstitute(row: TenantCloneRow) -> Result<Self, DomainError> {
        check_row(&row)?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            source: row.source,
            target: row.target,
            parts: row.parts,
            copied: row.copied,
            state: row.state,
            started_at: row.started_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The clone.
    #[must_use]
    pub fn id(&self) -> &TenantCloneId {
        &self.id
    }

    /// The organization both tenants belong to.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The tenant copied from.
    #[must_use]
    pub fn source(&self) -> &TenantId {
        &self.source
    }

    /// The tenant filled.
    #[must_use]
    pub fn target(&self) -> &TenantId {
        &self.target
    }

    /// What is copied.
    #[must_use]
    pub fn parts(&self) -> &[ClonePart] {
        &self.parts
    }

    /// What was copied so far.
    #[must_use]
    pub fn copied(&self) -> &[ClonePart] {
        &self.copied
    }

    /// Where it is.
    #[must_use]
    pub fn state(&self) -> CloneState {
        self.state
    }

    /// When it started.
    #[must_use]
    pub fn started_at(&self) -> OffsetDateTime {
        self.started_at
    }

    /// The parts still to copy, in the order a worker copies them.
    #[must_use]
    pub fn remaining(&self) -> Vec<ClonePart> {
        ClonePart::ALL
            .into_iter()
            .filter(|part| self.parts.contains(part) && !self.copied.contains(part))
            .collect()
    }

    /// Refuses unless this clone is copying `part` from `source` into
    /// `target` now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the clone has ended.
    /// - [`DomainError::Forbidden`] when the tenants are not this clone's,
    ///   or it does not copy `part`.
    pub fn ensure_copies(
        &self,
        part: ClonePart,
        source: &TenantId,
        target: &TenantId,
    ) -> Result<(), DomainError> {
        self.ensure_copying()?;
        if self.source != *source || self.target != *target {
            return Err(DomainError::forbidden(message!(
                "tenant-the-clone-copies-between-other-tenants",
                "the clone copies between other tenants"
            )));
        }
        if !self.parts.contains(&part) {
            return Err(DomainError::forbidden(message!(
                "tenant-the-clone-does-not-copy",
                format!("the clone does not copy {}", part.as_str())
            )));
        }
        Ok(())
    }

    /// Records that `part` was copied. Completes the clone, raising
    /// `tenant.clone_completed`, once the last part is. A part already
    /// copied is left as it is.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the clone has ended.
    /// - [`DomainError::Validation`] when the clone does not copy `part`.
    pub fn mark_copied(&mut self, part: ClonePart) -> Result<(), DomainError> {
        self.ensure_copying()?;
        if !self.parts.contains(&part) {
            return Err(DomainError::invalid(message!(
                "tenant-the-clone-does-not-copy",
                format!("the clone does not copy {}", part.as_str())
            )));
        }
        if !self.copied.contains(&part) {
            self.copied.push(part);
        }
        if self.remaining().is_empty() {
            self.complete();
        }
        Ok(())
    }

    /// Stops the clone for `reason`. Raises `tenant.clone_failed`. What was
    /// copied stays in the target.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the clone has ended.
    pub fn fail(&mut self, reason: CloneFailure) -> Result<(), DomainError> {
        self.ensure_copying()?;
        let at = crate::shared::clock::now();
        self.state = CloneState::Failed { at, reason };
        self.raise(TenantCloneFailed {
            clone_id: self.id,
            reason,
            occurred_at: at,
        });
        Ok(())
    }

    /// Marks the clone complete and raises it.
    fn complete(&mut self) {
        let at = crate::shared::clock::now();
        self.state = CloneState::Completed { at };
        self.raise(TenantCloneCompleted {
            clone_id: self.id,
            occurred_at: at,
        });
    }

    /// Refuses a step on a clone that has ended.
    fn ensure_copying(&self) -> Result<(), DomainError> {
        if self.state != CloneState::Copying {
            return Err(DomainError::conflict(message!(
                "tenant-the-clone-has-ended",
                "the clone has ended"
            )));
        }
        Ok(())
    }

    /// Keeps `event` as a record of the target tenant until it is taken.
    fn raise(&mut self, event: impl TenantEventBody + 'static) {
        self.raised.raise_tenant(self.target, event);
    }
}

/// A clone's records are filed under the tenant it fills, so taking them
/// needs no scope.
impl RaisesComplete for TenantClone {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Refuses copying `source` into `target` unless both are distinct
/// tenants of one organization, `source` still holds its setup and
/// `target` can still take one.
fn ensure_pair(source: &Tenant, target: &Tenant) -> Result<(), DomainError> {
    if source.organization_id() != target.organization_id() {
        return Err(DomainError::forbidden(message!(
            "tenant-a-clone-copies-between-tenants-of",
            "a clone copies between tenants of one organization"
        )));
    }
    if source.id() == target.id() {
        return Err(DomainError::invalid(message!(
            "tenant-a-tenant-is-not-cloned-into",
            "a tenant is not cloned into itself"
        )));
    }
    if matches!(
        source.status(),
        TenantStatus::Archived | TenantStatus::Deleted
    ) {
        return Err(DomainError::conflict(message!(
            "tenant-the-source-tenant-is-closed",
            "the source tenant is closed"
        )));
    }
    if !target.status().is_open() {
        return Err(DomainError::conflict(message!(
            "tenant-only-a-provisioning-or-active-tenant",
            "only a provisioning or active tenant is filled by a clone"
        )));
    }
    Ok(())
}

/// Refuses an empty list of parts, or one naming a part twice.
fn ensure_parts(parts: &[ClonePart]) -> Result<(), DomainError> {
    validate_count("clone_parts", parts.len(), 1..=ClonePart::ALL.len())?;
    if first_repeat(parts.iter().copied()).is_some() {
        return Err(DomainError::invalid(message!(
            "tenant-a-clone-names-each-part-once",
            "a clone names each part once"
        )));
    }
    Ok(())
}

/// Refuses a stored clone that breaks a rule the clone keeps.
fn check_row(row: &TenantCloneRow) -> Result<(), DomainError> {
    let complete = matches!(row.state, CloneState::Completed { .. });
    RowCheck::of("tenant_clone")
        .holds(row.source != row.target, "a tenant cloned into itself")
        .holds(!row.parts.is_empty(), "no part to copy")
        .holds(
            first_repeat(row.parts.iter().copied()).is_none()
                && first_repeat(row.copied.iter().copied()).is_none(),
            "a part named twice",
        )
        .holds(
            row.copied.iter().all(|part| row.parts.contains(part)),
            "a copied part it never asked for",
        )
        .holds(
            !complete || row.copied.len() == row.parts.len(),
            "complete with a part missing",
        )
        .in_order_if(
            row.started_at,
            row.state.ended_at(),
            "ended before it started",
        )
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::compliance_limits::ComplianceLimits;
    use crate::domains::tenant::fixtures::{Member, acme_params, active};
    use crate::domains::tenant::lifecycle::ProvisionTenantParams;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;
    use crate::types::ActedBy;

    /// A tenant of `organization`, just provisioned by the platform.
    fn tenant_of(organization: OrganizationId) -> Tenant {
        Tenant::provision(
            ProvisionTenantParams {
                id: TenantId::new(),
                organization_id: organization,
                ..acme_params()
            },
            &ComplianceLimits::default(),
            ActedBy::Platform,
        )
        .unwrap()
    }

    /// Acme's production tenant, active, and a staging tenant of the same
    /// organization, just provisioned.
    fn production_and_staging() -> (Tenant, Tenant) {
        let production = active();
        let staging = tenant_of(*production.organization_id());
        (production, staging)
    }

    /// A clone of settings and routes from production into staging, started
    /// by the platform.
    fn started() -> TenantClone {
        let (production, staging) = production_and_staging();
        TenantClone::start(
            vec![ClonePart::Settings, ClonePart::Routes],
            &production,
            &staging,
            ActedBy::Platform,
        )
        .unwrap()
    }

    /// Ann, who may make Acme's tenants, clones production's settings into
    /// staging. The clone copies between them and is filed under staging.
    #[test]
    fn a_member_who_may_make_tenants_starts_a_clone() {
        let (production, staging) = production_and_staging();
        let ann = Member::of(&production, &[LifecycleStep::Provision]);

        let mut clone = TenantClone::start(
            vec![ClonePart::Settings],
            &production,
            &staging,
            ActedBy::By(&ann),
        )
        .unwrap();

        assert_eq!(clone.source(), production.id());
        assert_eq!(clone.target(), staging.id());
        assert_eq!(clone.state(), CloneState::Copying);
        let events = clone.take_events();
        assert_eq!(events[0].event_type().to_string(), "tenant.clone_started");
        assert_eq!(events[0].tenant_id(), Some(staging.id()));
    }

    /// A member with only suspension rights and a member of another
    /// organization cannot start a clone of the tenant's routes.
    #[test]
    fn a_clone_needs_the_right_to_make_tenants() {
        let (production, staging) = production_and_staging();
        let sam = Member::of(&production, &[LifecycleStep::Suspend]);
        let eve = Member::elsewhere();

        for by in [&sam, &eve] {
            let refused = TenantClone::start(
                vec![ClonePart::Routes],
                &production,
                &staging,
                ActedBy::By(by),
            );
            assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        }
    }

    /// Even the platform cannot start a clone between tenants in different
    /// organizations.
    #[test]
    fn a_clone_never_crosses_organizations() {
        let production = active();
        let eves = tenant_of(OrganizationId::new());

        let refused = TenantClone::start(
            vec![ClonePart::Routes],
            &production,
            &eves,
            ActedBy::Platform,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A clone of production into production, one naming no part and one
    /// naming routes twice are refused as invalid.
    #[test]
    fn a_clone_needs_two_tenants_and_distinct_parts() {
        let (production, staging) = production_and_staging();

        let into_itself = TenantClone::start(
            vec![ClonePart::Routes],
            &production,
            &production,
            ActedBy::Platform,
        );
        let nothing = TenantClone::start(Vec::new(), &production, &staging, ActedBy::Platform);
        let twice = TenantClone::start(
            vec![ClonePart::Routes, ClonePart::Routes],
            &production,
            &staging,
            ActedBy::Platform,
        );

        assert!(matches!(into_itself, Err(DomainError::Validation(_))));
        assert!(matches!(nothing, Err(DomainError::Validation(_))));
        assert!(matches!(twice, Err(DomainError::Validation(_))));
    }

    /// An archived production tenant is cloned, and a staging tenant that
    /// was archived is filled. Both are refused as conflicts.
    #[test]
    fn a_closed_tenant_neither_gives_nor_takes_a_setup() {
        let (production, staging) = production_and_staging();
        let mut archived = tenant_of(*production.organization_id());
        archived.activate(ActedBy::Platform).unwrap();
        archived.archive(ActedBy::Platform).unwrap();

        let from_archived = TenantClone::start(
            vec![ClonePart::Routes],
            &archived,
            &staging,
            ActedBy::Platform,
        );
        let into_archived = TenantClone::start(
            vec![ClonePart::Routes],
            &production,
            &archived,
            ActedBy::Platform,
        );

        assert!(matches!(from_archived, Err(DomainError::Conflict(_))));
        assert!(matches!(into_archived, Err(DomainError::Conflict(_))));
    }

    /// The worker copies settings, then routes. After the last part the
    /// clone is complete and raises `tenant.clone_completed`.
    #[test]
    fn copying_the_last_part_completes_the_clone() {
        let mut clone = started();
        let _ = clone.take_events();

        clone.mark_copied(ClonePart::Settings).unwrap();
        assert_eq!(clone.remaining(), vec![ClonePart::Routes]);
        clone.mark_copied(ClonePart::Routes).unwrap();

        assert!(matches!(clone.state(), CloneState::Completed { .. }));
        assert_eq!(
            raised_complete_names(&mut clone),
            vec!["tenant.clone_completed"]
        );
    }

    /// The worker reports branding copied for a clone that never asked for
    /// it. It is refused, and nothing is recorded as copied.
    #[test]
    fn a_part_the_clone_does_not_copy_is_never_marked() {
        let mut clone = started();

        let refused = clone.mark_copied(ClonePart::Branding);

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert!(clone.copied().is_empty());
    }

    /// A clone fails because its source was archived. It raises
    /// `tenant.clone_failed`, and no later step moves it.
    #[test]
    fn a_failed_clone_takes_no_more_steps() {
        let mut clone = started();
        let _ = clone.take_events();

        clone.fail(CloneFailure::SourceGone).unwrap();

        assert!(matches!(
            clone.mark_copied(ClonePart::Routes),
            Err(DomainError::Conflict(_))
        ));
        assert!(matches!(
            clone.fail(CloneFailure::CopyFailed),
            Err(DomainError::Conflict(_))
        ));
        assert_eq!(
            raised_complete_names(&mut clone),
            vec!["tenant.clone_failed"]
        );
    }

    /// A clone authorizes settings for its own source and target, but rejects
    /// another target or branding that was not requested.
    #[test]
    fn a_clone_vouches_only_for_its_own_tenants_and_parts() {
        let clone = started();
        let (source, target) = (*clone.source(), *clone.target());

        assert!(
            clone
                .ensure_copies(ClonePart::Settings, &source, &target)
                .is_ok()
        );
        assert!(matches!(
            clone.ensure_copies(ClonePart::Settings, &source, &TenantId::new()),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            clone.ensure_copies(ClonePart::Branding, &source, &target),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// The stored form of `clone`.
    fn row_of(clone: &TenantClone) -> TenantCloneRow {
        TenantCloneRow {
            id: clone.id,
            organization_id: clone.organization_id,
            source: clone.source,
            target: clone.target,
            parts: clone.parts.clone(),
            copied: clone.copied.clone(),
            state: clone.state,
            started_at: clone.started_at,
        }
    }

    /// A clone is stored and read back. It comes back as it was, with
    /// nothing raised.
    #[test]
    fn a_stored_clone_reads_back() {
        let clone = started();

        let mut read = TenantClone::reconstitute(row_of(&clone)).unwrap();

        assert_eq!(read.parts(), clone.parts());
        assert!(raised_complete_names(&mut read).is_empty());
    }

    /// Stored clones are corrupt when they copy a tenant into itself, record
    /// an unrequested part or claim completion with a requested part missing.
    #[test]
    fn a_stored_clone_breaking_its_rules_is_refused() {
        let clone = started();
        let into_itself = TenantCloneRow {
            target: clone.source,
            ..row_of(&clone)
        };
        let stray_part = TenantCloneRow {
            copied: vec![ClonePart::Branding],
            ..row_of(&clone)
        };
        let half_done = TenantCloneRow {
            copied: vec![ClonePart::Settings],
            state: CloneState::Completed {
                at: clone.started_at,
            },
            ..row_of(&clone)
        };

        for row in [into_itself, stray_part, half_done] {
            assert!(refused_as_corrupt(&TenantClone::reconstitute(row)));
        }
    }

    /// Every part reads back from its stored name, and no part is called
    /// `users`.
    #[test]
    fn every_part_reads_back_and_people_are_no_part() {
        for part in ClonePart::ALL {
            assert_eq!(ClonePart::parse(part.as_str()), Some(part));
        }
        assert_eq!(ClonePart::parse("users"), None);
    }
}
