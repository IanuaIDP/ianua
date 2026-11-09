use std::fmt;

use time::{Duration, OffsetDateTime};

use crate::shared::model::two_cases::two_cases;

/// How long an archived tenant waits before it may be deleted.
///
/// Until then it can be restored. One owner who archives a tenant by
/// mistake, or with a stolen session, cannot wipe it in the same minute.
pub const ARCHIVE_GRACE: Duration = Duration::days(30);

/// Tenant lifecycle state.
///
/// It decides what a tenant may do right now. Every move between states is
/// checked by [`can_transition_to`](Self::can_transition_to).
///
/// ```text
/// Provisioning ──→ Active ←──→ Suspended
///      │            ▲  │          │
///      │    restore │  ▼          │
///      └─────────→ Archived ←─────┘
///                    │
///                    ▼
///                 Deleted
/// ```
///
/// A tenant still provisioning is archived only when the platform stops its
/// setup, as when its organization closes half way through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TenantStatus {
    /// The first state, while default roles, sign-in settings and signing
    /// keys are set up. Its users may already sign in, so the first sign-in
    /// can happen while the last steps finish.
    Provisioning,

    /// Fully working. Sign-in and API access work as normal.
    Active,

    /// Frozen by its organization or by the platform. Sessions end and new
    /// sign-ins are refused. The data is kept and comes back on
    /// reactivation. See [`PlatformHold`] for who may reactivate it.
    Suspended,

    /// Soft-deleted. Sessions end and the data is kept. It can be restored
    /// to `Active` until it is deleted, and deleted only once
    /// [`ARCHIVE_GRACE`] has passed.
    Archived,

    /// Terminal state. All tenant data has been wiped. Irreversible.
    Deleted,
}

/// A refused move between two tenant statuses.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("cannot transition from {from} to {to}")]
pub struct InvalidTenantTransition {
    /// The status the tenant was in.
    pub from: TenantStatus,
    /// The status it was asked to move to.
    pub to: TenantStatus,
}

impl TenantStatus {
    /// Whether a tenant in this status serves its own people: sign-in and
    /// every request made in the tenant's name.
    ///
    /// A `Provisioning` tenant is open, because its first sign-in can happen
    /// while the last steps finish. A suspended, archived or deleted tenant
    /// is closed to everything done in its name.
    ///
    /// The organization or an operator can still act on the tenant from
    /// outside, for example to reactivate, export or delete it. Those actions
    /// are not done in the tenant's name, so this does not stop them.
    #[must_use]
    pub fn is_open(&self) -> bool {
        match self {
            Self::Provisioning | Self::Active => true,
            Self::Suspended | Self::Archived | Self::Deleted => false,
        }
    }

    /// Every status a tenant can move to from this one.
    ///
    /// Admin screens use it to show the actions on offer.
    #[must_use]
    pub fn allowed_transitions(&self) -> &'static [TenantStatus] {
        match self {
            Self::Provisioning => &[Self::Active, Self::Archived],
            Self::Active => &[Self::Suspended, Self::Archived],
            Self::Suspended => &[Self::Active, Self::Archived],
            Self::Archived => &[Self::Active, Self::Deleted],
            Self::Deleted => &[],
        }
    }

    /// Whether a tenant may move from this status to `target`.
    #[must_use]
    pub fn can_transition_to(&self, target: TenantStatus) -> bool {
        self.allowed_transitions().contains(&target)
    }

    /// Gives `to` when a tenant may move there from this status.
    ///
    /// # Errors
    ///
    /// - [`InvalidTenantTransition`] when `to` is not reachable from this
    ///   status.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTenantTransition> {
        if !self.can_transition_to(to) {
            return Err(InvalidTenantTransition { from: self, to });
        }
        Ok(to)
    }
}

impl fmt::Display for TenantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provisioning => f.write_str("provisioning"),
            Self::Active => f.write_str("active"),
            Self::Suspended => f.write_str("suspended"),
            Self::Archived => f.write_str("archived"),
            Self::Deleted => f.write_str("deleted"),
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidTenantTransition);

two_cases! {
    /// Whether the platform holds a tenant out of service.
    ///
    /// The platform suspends a tenant for abuse or an unpaid bill. Its
    /// organization must not lift that itself. A tenant the platform holds
    /// comes back only through the platform. Stored as the `platform_hold`
    /// flag.
    pub enum PlatformHold {
        /// The platform suspended or archived it, and only the platform
        /// brings it back.
        Held => true,
        /// Its organization may bring it back.
        Free => false,
    }
}

/// Whether a tenant was archived, and when.
///
/// The wait before deletion runs from this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Archival {
    /// Never archived, or restored since.
    NotArchived,
    /// Archived at this instant.
    Since(OffsetDateTime),
}

impl Archival {
    /// The archival a stored time records. No time means not archived.
    #[must_use]
    pub fn from_stored(archived_at: Option<OffsetDateTime>) -> Self {
        archived_at.map_or(Self::NotArchived, Self::Since)
    }

    /// When it was archived, if it was. Storage keeps it in this form.
    #[must_use]
    pub fn at(self) -> Option<OffsetDateTime> {
        match self {
            Self::NotArchived => None,
            Self::Since(at) => Some(at),
        }
    }

    /// The first moment the tenant may be deleted, if it is archived.
    #[must_use]
    pub fn deletable_from(self) -> Option<OffsetDateTime> {
        self.at().map(|at| at.saturating_add(ARCHIVE_GRACE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Suspended, archived and deleted statuses all report that the tenant
    /// is closed to requests made in its name.
    #[test]
    fn a_shut_off_tenant_serves_nobody() {
        for status in [
            TenantStatus::Suspended,
            TenantStatus::Archived,
            TenantStatus::Deleted,
        ] {
            assert!(!status.is_open(), "{status:?}");
        }
    }

    /// Active and provisioning tenants both read as open. The founder's first
    /// sign-in can then happen while provisioning finishes.
    #[test]
    fn a_tenant_coming_up_or_active_is_open() {
        assert!(TenantStatus::Active.is_open());
        assert!(TenantStatus::Provisioning.is_open());
    }

    /// A tenant finishes provisioning and moves to active.
    #[test]
    fn provisioning_can_activate() {
        assert_eq!(
            TenantStatus::Provisioning.try_transition(TenantStatus::Active),
            Ok(TenantStatus::Active)
        );
    }

    /// An operator suspends an active tenant. The move is allowed.
    #[test]
    fn active_can_suspend() {
        assert_eq!(
            TenantStatus::Active.try_transition(TenantStatus::Suspended),
            Ok(TenantStatus::Suspended)
        );
    }

    /// An active tenant is archived. The move is allowed.
    #[test]
    fn active_can_archive() {
        assert_eq!(
            TenantStatus::Active.try_transition(TenantStatus::Archived),
            Ok(TenantStatus::Archived)
        );
    }

    /// A suspended tenant is reactivated and becomes active again.
    #[test]
    fn suspended_can_reactivate() {
        assert_eq!(
            TenantStatus::Suspended.try_transition(TenantStatus::Active),
            Ok(TenantStatus::Active)
        );
    }

    /// A suspended tenant is archived without being reactivated first.
    #[test]
    fn suspended_can_archive() {
        assert_eq!(
            TenantStatus::Suspended.try_transition(TenantStatus::Archived),
            Ok(TenantStatus::Archived)
        );
    }

    /// An archived tenant is deleted. The move is allowed.
    #[test]
    fn archived_can_delete() {
        assert_eq!(
            TenantStatus::Archived.try_transition(TenantStatus::Deleted),
            Ok(TenantStatus::Deleted)
        );
    }

    /// A tenant still provisioning is suspended. The move is refused, and
    /// the refusal names both statuses.
    #[test]
    fn provisioning_cannot_suspend() {
        let err = TenantStatus::Provisioning
            .try_transition(TenantStatus::Suspended)
            .unwrap_err();

        assert_eq!(err.from, TenantStatus::Provisioning);
        assert_eq!(err.to, TenantStatus::Suspended);
    }

    /// Acme closes while its staging tenant is still being set up. The
    /// setup is stopped by archiving the tenant, so the move is allowed.
    #[test]
    fn provisioning_can_archive() {
        assert_eq!(
            TenantStatus::Provisioning.try_transition(TenantStatus::Archived),
            Ok(TenantStatus::Archived)
        );
    }

    /// A tenant still provisioning is deleted. The move is refused.
    #[test]
    fn provisioning_cannot_delete() {
        assert!(
            TenantStatus::Provisioning
                .try_transition(TenantStatus::Deleted)
                .is_err()
        );
    }

    /// An active tenant is deleted without being archived first. The move is
    /// refused, so data always passes through archive before it is wiped.
    #[test]
    fn active_cannot_delete_directly() {
        assert!(
            TenantStatus::Active
                .try_transition(TenantStatus::Deleted)
                .is_err()
        );
    }

    /// An active tenant is moved back to provisioning. The move is refused.
    #[test]
    fn active_cannot_return_to_provisioning() {
        assert!(
            TenantStatus::Active
                .try_transition(TenantStatus::Provisioning)
                .is_err()
        );
    }

    /// Acme archived its tenant by mistake and brings it back before it is
    /// deleted. The move back to active is allowed.
    #[test]
    fn an_archived_tenant_can_be_restored() {
        assert_eq!(
            TenantStatus::Archived.try_transition(TenantStatus::Active),
            Ok(TenantStatus::Active)
        );
    }

    /// A tenant archived today may be deleted thirty days from now. One never
    /// archived has no such date.
    #[test]
    fn an_archived_tenant_may_be_deleted_once_the_grace_has_passed() {
        let archived_on = crate::shared::clock::now();

        let archival = Archival::from_stored(Some(archived_on));

        assert_eq!(
            archival.deletable_from(),
            Some(archived_on + Duration::days(30))
        );
        assert_eq!(Archival::from_stored(None).deletable_from(), None);
    }

    /// An archived tenant is suspended. The move is refused.
    #[test]
    fn archived_cannot_suspend() {
        assert!(
            TenantStatus::Archived
                .try_transition(TenantStatus::Suspended)
                .is_err()
        );
    }

    /// A deleted tenant is moved to active, provisioning, suspended or
    /// archived. Every move is refused, since its data is gone.
    #[test]
    fn deleted_cannot_transition_anywhere() {
        assert!(
            TenantStatus::Deleted
                .try_transition(TenantStatus::Active)
                .is_err()
        );
        assert!(
            TenantStatus::Deleted
                .try_transition(TenantStatus::Provisioning)
                .is_err()
        );
        assert!(
            TenantStatus::Deleted
                .try_transition(TenantStatus::Suspended)
                .is_err()
        );
        assert!(
            TenantStatus::Deleted
                .try_transition(TenantStatus::Archived)
                .is_err()
        );
    }

    /// An active tenant is activated, or a suspended one suspended. Both are
    /// refused, so no event records a change that did not happen.
    #[test]
    fn self_transition_is_rejected() {
        assert!(
            TenantStatus::Active
                .try_transition(TenantStatus::Active)
                .is_err()
        );
        assert!(
            TenantStatus::Suspended
                .try_transition(TenantStatus::Suspended)
                .is_err()
        );
    }

    /// An admin screen for a deleted tenant offers no actions.
    #[test]
    fn deleted_has_no_transitions() {
        assert!(TenantStatus::Deleted.allowed_transitions().is_empty());
    }

    /// A provisioning tenant moves on to active, or is archived when its
    /// setup is stopped.
    #[test]
    fn provisioning_activates_or_is_archived() {
        assert_eq!(
            TenantStatus::Provisioning.allowed_transitions(),
            &[TenantStatus::Active, TenantStatus::Archived]
        );
    }

    /// Each status prints as its lowercase name, such as `provisioning`.
    #[test]
    fn display_is_lowercase() {
        assert_eq!(TenantStatus::Provisioning.to_string(), "provisioning");
        assert_eq!(TenantStatus::Active.to_string(), "active");
        assert_eq!(TenantStatus::Suspended.to_string(), "suspended");
        assert_eq!(TenantStatus::Archived.to_string(), "archived");
        assert_eq!(TenantStatus::Deleted.to_string(), "deleted");
    }

    /// An active tenant is deleted directly. The refusal reads "cannot
    /// transition from active to deleted".
    #[test]
    fn error_message_shows_both_states() {
        let err = TenantStatus::Active
            .try_transition(TenantStatus::Deleted)
            .unwrap_err();

        assert_eq!(err.to_string(), "cannot transition from active to deleted");
    }

    /// A deleted tenant is reactivated. The refusal keeps its exact words,
    /// since callers show this message to people.
    #[test]
    fn the_refusal_message_is_unchanged() {
        let refusal = TenantStatus::Deleted
            .try_transition(TenantStatus::Active)
            .unwrap_err();

        assert_eq!(
            refusal.to_string(),
            "cannot transition from deleted to active"
        );
    }
}
