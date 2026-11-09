//! Requests for a copy of a person's data, under GDPR Article 15, the right
//! of access, and Article 20, the right to take one's data elsewhere.
//!
//! A request is asked by the person themselves, or by staff on their
//! behalf. An adapter gathers the sections the request names into a file.
//! The file is the person's: only they download it, for a week after it is
//! ready, and then it is gone.

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::identity::account::control::{
    AccountAction, AccountControlCheck, SignedInPerson, ensure_holder,
};
use crate::domains::identity::account::user::User;
use crate::domains::identity::events::export::{
    DataExportDownloaded, DataExportExpired, DataExportReady, DataExportRequested,
};
use crate::domains::identity::privacy::export_state::{ExportState, ExportStatus};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{DataExportId, UserId};

/// How long a finished export may be downloaded.
pub const DOWNLOAD_WINDOW: Duration = Duration::days(7);

/// What a person asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportScope {
    /// Everything kept about them, under the right of access.
    Access,
    /// What they gave the service themselves, in a form another service
    /// reads, under the right to take it elsewhere.
    Portability,
}

/// One part of an export.
///
/// No section holds a secret: no password hash, factor secret, recovery
/// code, key or token is ever written into an export. A section tells
/// what exists, such as that a passkey named "Laptop" was added on a day,
/// never what would let someone use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportSection {
    /// The account: address, name, language, timezone, status, the
    /// person's details and the directory's records about them.
    Profile,
    /// The custom attributes stored on them.
    Attributes,
    /// Every consent they gave or withdrew, with its version.
    Consents,
    /// The apps they let act for them, and what each may do.
    AppGrants,
    /// The outside identity providers linked to the account.
    LinkedIdentities,
    /// The roles and groups they hold.
    RolesAndGroups,
    /// Their sessions still kept, open or ended, with where and when each
    /// began.
    Sessions,
    /// Their sign-ins, failed ones included: those they made, the lockouts
    /// of their account, and the failed attempts typed with each address
    /// while their account held it.
    SignInHistory,
    /// The failed sign-ins counted now against the address they sign in
    /// with, from every network together.
    FailedSignInCount,
    /// The countries they signed in from, and where they last signed in.
    SignInPlaces,
    /// The links they were sent to reset their password: who asked, when,
    /// and how each ended. Never the link.
    PasswordResets,
    /// The invitations sent to their account: who sent them, when, and how
    /// each was answered. Never the link.
    Invitations,
    /// The emergency access given to them: what it allowed, why, who
    /// approved it, and until when.
    BreakGlassGrants,
    /// Their second factors, passkeys and remembered devices, by name and
    /// date.
    Devices,
    /// The notices sent to them about their own account, and how they
    /// chose to be told.
    Notifications,
    /// The times staff asked to act as them for support, and how each
    /// went.
    SupportAccess,
    /// The audit trail's records of what staff or an operator did while
    /// acting as them.
    ActedAsThem,
    /// The audit trail's records of what they did.
    Activity,
}

impl ExportSection {
    /// The section's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Attributes => "attributes",
            Self::Consents => "consents",
            Self::AppGrants => "app_grants",
            Self::LinkedIdentities => "linked_identities",
            Self::RolesAndGroups => "roles_and_groups",
            Self::Sessions => "sessions",
            Self::SignInHistory => "sign_in_history",
            Self::FailedSignInCount => "failed_sign_in_count",
            Self::SignInPlaces => "sign_in_places",
            Self::PasswordResets => "password_resets",
            Self::Invitations => "invitations",
            Self::BreakGlassGrants => "break_glass_grants",
            Self::Devices => "devices",
            Self::Notifications => "notifications",
            Self::SupportAccess => "support_access",
            Self::ActedAsThem => "acted_as_them",
            Self::Activity => "activity",
        }
    }
}

impl ExportScope {
    /// The sections an export of this scope holds.
    ///
    /// Access holds everything kept about the person. Portability holds
    /// what they gave the service themselves: their profile, their
    /// attributes and their consents.
    #[must_use]
    pub fn sections(self) -> &'static [ExportSection] {
        match self {
            Self::Access => &[
                ExportSection::Profile,
                ExportSection::Attributes,
                ExportSection::Consents,
                ExportSection::AppGrants,
                ExportSection::LinkedIdentities,
                ExportSection::RolesAndGroups,
                ExportSection::Sessions,
                ExportSection::SignInHistory,
                ExportSection::FailedSignInCount,
                ExportSection::SignInPlaces,
                ExportSection::PasswordResets,
                ExportSection::Invitations,
                ExportSection::BreakGlassGrants,
                ExportSection::Devices,
                ExportSection::Notifications,
                ExportSection::SupportAccess,
                ExportSection::ActedAsThem,
                ExportSection::Activity,
            ],
            Self::Portability => &[
                ExportSection::Profile,
                ExportSection::Attributes,
                ExportSection::Consents,
            ],
        }
    }

    /// The scope's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Portability => "portability",
        }
    }
}

/// Who asked for an export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportAskedBy {
    /// The person themselves, signed in.
    Holder,
    /// Staff who may act on the account, for the person who asked them.
    Staff,
}

/// A request for a copy of one person's data.
#[derive(Debug)]
pub struct DataExportRequest<T: TenantScope> {
    id: DataExportId,
    user_id: UserId,
    scope: ExportScope,
    asked_by: ExportAskedBy,
    state: ExportState,
    requested_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// An export request as storage keeps it, checked again by
/// [`DataExportRequest::reconstitute`].
#[derive(Clone, Copy)]
pub struct DataExportRequestRow {
    /// The request's id.
    pub id: DataExportId,
    /// The person whose data it copies.
    pub user_id: UserId,
    /// What they asked for.
    pub scope: ExportScope,
    /// Who asked.
    pub asked_by: ExportAskedBy,
    /// Where it stands. See [`ExportState::from_stored`].
    pub state: ExportState,
    /// When it was asked for.
    pub requested_at: OffsetDateTime,
}

impl<T: TenantScope> DataExportRequest<T> {
    /// Asks for a copy of `account`'s data, by its holder. Raises
    /// `identity.data_export_requested`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone other than the person is
    ///   signed in.
    pub fn request(
        account: &User<T>,
        scope: ExportScope,
        by: &impl SignedInPerson<T>,
    ) -> Result<Self, DomainError> {
        ensure_holder(by, account.id())?;
        Ok(Self::open(account, scope, ExportAskedBy::Holder))
    }

    /// Requests an authorized export on the account holder's behalf; the file goes only to them.
    /// Raises `identity.data_export_requested`.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another account's control, missing authority,
    /// or permissions held by the account but not the actor.
    pub fn request_for(
        account: &User<T>,
        scope: ExportScope,
        control: &impl AccountControlCheck,
    ) -> Result<Self, DomainError> {
        control.ensure_allowed(account.id(), AccountAction::Export)?;
        Ok(Self::open(account, scope, ExportAskedBy::Staff))
    }

    fn open(account: &User<T>, scope: ExportScope, asked_by: ExportAskedBy) -> Self {
        let now = crate::shared::clock::now();
        let mut request = Self {
            id: DataExportId::new(),
            user_id: *account.id(),
            scope,
            asked_by,
            state: ExportState::Requested,
            requested_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        request.raised.raise(DataExportRequested {
            user_id: request.user_id,
            scope,
            occurred_at: now,
        });
        request
    }

    /// Rebuilds an export request from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it was ready
    ///   before it was asked for, or was kept for longer or shorter than
    ///   [`DOWNLOAD_WINDOW`].
    pub fn reconstitute(row: DataExportRequestRow) -> Result<Self, DomainError> {
        RowCheck::of("data export request")
            .in_order_if(
                row.requested_at,
                row.state.ready_at(),
                "ready before it was asked for",
            )
            .holds(
                row.state.keeps_the_download_window(DOWNLOAD_WINDOW),
                "a download window no export has",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            scope: row.scope,
            asked_by: row.asked_by,
            state: row.state,
            requested_at: row.requested_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The request's id.
    #[must_use]
    pub fn id(&self) -> &DataExportId {
        &self.id
    }

    /// The person whose data it copies.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// What they asked for.
    #[must_use]
    pub fn scope(&self) -> ExportScope {
        self.scope
    }

    /// The sections the export holds.
    #[must_use]
    pub fn sections(&self) -> &'static [ExportSection] {
        self.scope.sections()
    }

    /// Who asked.
    #[must_use]
    pub fn asked_by(&self) -> ExportAskedBy {
        self.asked_by
    }

    /// Where it stands, with when it was ready and until when it may be
    /// downloaded.
    #[must_use]
    pub fn state(&self) -> ExportState {
        self.state
    }

    /// Where it stands.
    #[must_use]
    pub fn status(&self) -> ExportStatus {
        self.state.status()
    }

    /// When it was asked for.
    #[must_use]
    pub fn requested_at(&self) -> OffsetDateTime {
        self.requested_at
    }

    /// Whether it is still asked for or ready to download, so a new request
    /// for the same person waits on it.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !matches!(self.state, ExportState::Expired)
    }

    /// Marks the export ready at `now`, once the file is gathered: it may
    /// be downloaded for [`DOWNLOAD_WINDOW`]. Raises
    /// `identity.data_export_ready`. The caller mails the person that it is
    /// waiting for them.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not requested.
    pub fn mark_ready(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        let available_until = now.saturating_add(DOWNLOAD_WINDOW);
        self.move_to(ExportState::Ready {
            at: now,
            available_until,
        })?;
        self.raised.raise(DataExportReady {
            user_id: self.user_id,
            available_until,
            occurred_at: now,
        });
        Ok(())
    }

    /// Lets the person download the file, while it is ready. Raises
    /// `identity.data_export_downloaded`.
    ///
    /// The file holds all that is kept about the person, so it goes to
    /// them alone, whoever asked. Sam may view users and asked for Ann's
    /// export when she wrote to support. Without this check, he downloads
    /// her sign-in history, her devices and the apps she uses.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone other than the person is
    ///   signed in.
    /// - [`DomainError::Conflict`] when it is not ready yet, or its window
    ///   is over at `now`.
    pub fn download(
        &mut self,
        by: &impl SignedInPerson<T>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        ensure_holder(by, &self.user_id)?;
        if !self.state.downloadable_at(now) {
            return Err(DomainError::conflict(message!(
                "identity-the-export-is-not-ready-or",
                "the export is not ready, or its download window is over"
            )));
        }
        self.raised.raise(DataExportDownloaded {
            user_id: self.user_id,
            occurred_at: now,
        });
        Ok(())
    }

    /// Ends the download window once it is over at `now`. The caller
    /// deletes the file. Raises `identity.data_export_expired`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not ready, or its
    ///   window is not over at `now`.
    pub fn expire(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.state.downloadable_at(now) {
            return Err(DomainError::invalid_transition(message!(
                "audit-the-export-may-still-be-downloaded",
                "the export may still be downloaded"
            )));
        }
        self.move_to(ExportState::Expired)?;
        self.raised.raise(DataExportExpired {
            user_id: self.user_id,
            occurred_at: now,
        });
        Ok(())
    }

    fn move_to(&mut self, to: ExportState) -> Result<(), DomainError> {
        self.status().try_transition(to.status())?;
        self.state = to;
        Ok(())
    }
}

impl<T: TenantScope> Raises for DataExportRequest<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::stewardship::Stewardship;
    use crate::domains::identity::account::user::tests::signed_in_as;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::user;
    use crate::test_support::events::raised_names;

    fn ann() -> User<ResolvedTenant> {
        user(UserId::new(), "ann@example.com")
    }

    fn holding_on(
        account: &User<ResolvedTenant>,
        held: &'static [SystemPermission],
    ) -> AccountControl<'static> {
        AccountControl::assumed(
            anyone_holding(held),
            *account.id(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        )
    }

    fn asked_by_ann(account: &User<ResolvedTenant>) -> DataExportRequest<ResolvedTenant> {
        DataExportRequest::request(
            account,
            ExportScope::Access,
            &signed_in_as::<ResolvedTenant>(*account.id()),
        )
        .unwrap()
    }

    /// Ann asks for everything kept about her. The request waits, names her
    /// as the one who asked, holds every section and records the request.
    #[test]
    fn the_holder_asks_for_a_copy_of_their_data() {
        let account = ann();

        let mut request = asked_by_ann(&account);

        assert_eq!(request.status(), ExportStatus::Requested);
        assert_eq!(request.asked_by(), ExportAskedBy::Holder);
        assert!(request.sections().contains(&ExportSection::SignInHistory));
        assert_eq!(
            raised_names(&mut request),
            ["identity.data_export_requested"]
        );
    }

    /// Portability holds only what Ann gave the service: her profile,
    /// attributes and consents.
    #[test]
    fn portability_holds_what_the_person_gave() {
        assert_eq!(
            ExportScope::Portability.sections(),
            [
                ExportSection::Profile,
                ExportSection::Attributes,
                ExportSection::Consents
            ]
        );
    }

    /// Access exports include sign-in records, notices, invitations and support
    /// activity, and none of their section names repeat.
    #[test]
    fn access_holds_every_section_once() {
        let sections = ExportScope::Access.sections();

        for section in [
            ExportSection::Sessions,
            ExportSection::SignInHistory,
            ExportSection::SignInPlaces,
            ExportSection::FailedSignInCount,
            ExportSection::PasswordResets,
            ExportSection::Invitations,
            ExportSection::BreakGlassGrants,
            ExportSection::Notifications,
            ExportSection::SupportAccess,
            ExportSection::ActedAsThem,
        ] {
            assert!(sections.contains(&section), "{}", section.as_str());
        }
        let names: std::collections::HashSet<&str> =
            sections.iter().map(|section| section.as_str()).collect();
        assert_eq!(names.len(), sections.len());
    }

    /// Mallory's own sign-in cannot request Ann's personal data export.
    #[test]
    fn another_signed_in_person_cannot_ask_for_an_export() {
        let account = ann();
        let mallory = signed_in_as::<ResolvedTenant>(UserId::new());

        let refused = DataExportRequest::request(&account, ExportScope::Access, &mallory);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Staff need permission to view users to request Ann's export on her behalf;
    /// an authorized request records that staff asked for it.
    #[test]
    fn staff_ask_for_an_export_only_with_the_right_to_view_users() {
        let account = ann();
        let sam = holding_on(&account, &[]);
        let support = holding_on(&account, &[SystemPermission::Users(UserAction::View)]);

        let refused = DataExportRequest::request_for(&account, ExportScope::Access, &sam);
        let asked = DataExportRequest::request_for(&account, ExportScope::Access, &support);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(asked.unwrap().asked_by(), ExportAskedBy::Staff);
    }

    /// Once the file is gathered, Ann downloads it within the week.
    #[test]
    fn the_holder_downloads_a_ready_export() {
        let account = ann();
        let mut request = asked_by_ann(&account);
        let now = crate::shared::clock::now();
        request.mark_ready(now).unwrap();

        let downloaded = request.download(
            &signed_in_as::<ResolvedTenant>(*account.id()),
            now + Duration::days(6),
        );

        assert!(downloaded.is_ok());
    }

    /// Permission to request Ann's export on her behalf does not let another
    /// signed-in person download it.
    #[test]
    fn only_the_holder_downloads_an_export() {
        let account = ann();
        let support = holding_on(&account, &[SystemPermission::Users(UserAction::View)]);
        let mut request =
            DataExportRequest::request_for(&account, ExportScope::Access, &support).unwrap();
        let now = crate::shared::clock::now();
        request.mark_ready(now).unwrap();
        let sam = signed_in_as::<ResolvedTenant>(UserId::new());

        let refused = request.download(&sam, now);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// An export not gathered yet, and one whose week is over, cannot be
    /// downloaded.
    #[test]
    fn an_export_is_downloaded_only_inside_its_window() {
        let account = ann();
        let holder = signed_in_as::<ResolvedTenant>(*account.id());
        let mut request = asked_by_ann(&account);
        let now = crate::shared::clock::now();

        let early = request.download(&holder, now);
        request.mark_ready(now).unwrap();
        let late = request.download(&holder, now + DOWNLOAD_WINDOW);

        assert!(matches!(early, Err(DomainError::Conflict(_))));
        assert!(matches!(late, Err(DomainError::Conflict(_))));
    }

    /// After its week the export expires and is no longer open. Expiring it
    /// a day early is refused.
    #[test]
    fn an_export_expires_once_its_window_is_over() {
        let account = ann();
        let mut request = asked_by_ann(&account);
        let now = crate::shared::clock::now();
        request.mark_ready(now).unwrap();

        let early = request.expire(now + Duration::days(6));
        request.expire(now + DOWNLOAD_WINDOW).unwrap();

        assert!(matches!(early, Err(DomainError::InvalidTransition(_))));
        assert_eq!(request.status(), ExportStatus::Expired);
        assert!(!request.is_open());
    }

    /// A stored export ready a day before it was asked for is refused as
    /// corrupt.
    #[test]
    fn a_stored_export_ready_before_it_was_asked_for_is_refused() {
        let now = crate::shared::clock::now();
        let ready = now - Duration::days(1);
        let row = DataExportRequestRow {
            id: DataExportId::new(),
            user_id: UserId::new(),
            scope: ExportScope::Access,
            asked_by: ExportAskedBy::Holder,
            state: ExportState::Ready {
                at: ready,
                available_until: ready + DOWNLOAD_WINDOW,
            },
            requested_at: now,
        };

        assert!(refused_as_corrupt(
            &DataExportRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored export with a year-long download window is rejected as corrupt.
    #[test]
    fn a_stored_export_with_a_longer_window_is_refused() {
        let now = crate::shared::clock::now();
        let row = DataExportRequestRow {
            id: DataExportId::new(),
            user_id: UserId::new(),
            scope: ExportScope::Access,
            asked_by: ExportAskedBy::Holder,
            state: ExportState::Ready {
                at: now,
                available_until: now + Duration::days(365),
            },
            requested_at: now,
        };

        assert!(refused_as_corrupt(
            &DataExportRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
