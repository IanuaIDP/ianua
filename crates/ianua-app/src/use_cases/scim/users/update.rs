//! Update SCIM user: the directory changes parts of a user's record, their
//! address, their names, what it records about them (its `externalId`,
//! their department, manager and employee number), and whether they may
//! sign in.
//!
//! A new address is never proven by the directory's word, as one from an
//! administrator is not, and is always mailed a link to confirm it. An
//! account let back in with its address still unproven is mailed one too.
//! Switching an account off locks it and ends its sessions and the delegations it gave;
//! switching it on lets it back in. The domain decides which accounts the
//! directory may move: never one holding built-in permissions, and never
//! the tenant's last administrator out.

use std::sync::Arc;

use ianua_domain::domains::federation::scim::{DirectoryControl, ScimEndpoint};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user::directory::DirectorySwitch;
use ianua_domain::domains::identity::account::user_profile::{DirectoryRecords, PersonalDetails};
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, DisplayName, Email, Setting, UserId};

use crate::acting::ScimAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::ScimCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::ResetRequestStore;
use crate::ports::authorization::AccessRecordStore;
use crate::ports::federation::ScimStore;
use crate::ports::identity::UserStore;
use crate::services::identity::address_free::ensure_email_free;
use crate::services::identity::link_scopes::TenantLinkScopes;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::email::VerificationLinks;
use crate::use_cases::identity::users::sessions::sign_out::StandingRemoval;
use crate::use_cases::scim::sync::record_synced;
use crate::use_cases::scim::users::directory_account::{
    ConfirmationMail, confirmation_mailed, directory_reach,
};
use crate::use_cases::scim::users::fields::{AccountSwitch, ScimUserChange};

/// The changes a directory asks for, to which user.
pub struct UpdateScimRequest {
    /// The user being changed.
    pub user_id: UserId,
    /// The changes, applied in order.
    pub changes: Vec<ScimUserChange>,
}

/// The ports [`UpdateScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Records when the directory last synced.
    pub scim_store: Arc<dyn ScimStore>,
    /// Mails a new address the link that confirms it.
    pub verification_links: Arc<VerificationLinks>,
    /// Ends the password resets mailed to an address the user left.
    pub reset_requests: Arc<dyn ResetRequestStore>,
    /// Where the tenant's links point, from its records.
    pub link_scopes: TenantLinkScopes,
    /// Loads and saves users, and finds addresses already taken.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Ends a switched-off user's sessions and the delegations they gave.
    pub removal: StandingRemoval,
}

/// Changes parts of a tenant user's record for its directory.
pub struct UpdateScimUseCase {
    ports: UpdateScimPorts,
}

/// The directory acting on one account of one tenant.
struct Acting<'a> {
    tenant: &'a ScopedTenant,
    endpoint: &'a ScimEndpoint<ResolvedTenant>,
    control: DirectoryControl,
}

impl UpdateScimUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdateScimPorts) -> Self {
        Self { ports }
    }

    /// Applies each of `changes` to `user` in order.
    async fn all_applied(
        &self,
        acting: &Acting<'_>,
        user: &mut User<ResolvedTenant>,
        changes: Vec<ScimUserChange>,
    ) -> Result<(), AppError> {
        for change in changes {
            self.apply(acting, user, change).await?;
        }
        Ok(())
    }

    /// Applies `change` to `user`.
    async fn apply(
        &self,
        acting: &Acting<'_>,
        user: &mut User<ResolvedTenant>,
        change: ScimUserChange,
    ) -> Result<(), AppError> {
        match change {
            ScimUserChange::UserName(email) => self.change_email(acting, user, email).await,
            ScimUserChange::DisplayName(name) => rename(acting, user, name),
            ScimUserChange::Active(switch) => user
                .switch_by_directory(directory_switch(switch), &acting.control)
                .map_err(AppError::from_domain),
            ScimUserChange::GivenName(name) => {
                update_details(acting, user, |details| details.given_name = name)
            }
            ScimUserChange::FamilyName(name) => {
                update_details(acting, user, |details| details.family_name = name)
            }
            ScimUserChange::ExternalId(id) => {
                update_records(acting, user, |records| records.external_id = id)
            }
            ScimUserChange::Department(name) => {
                update_records(acting, user, |records| records.department = name)
            }
            ScimUserChange::Manager(manager) => self.set_manager(acting, user, manager).await,
            ScimUserChange::EmployeeNumber(number) => {
                update_records(acting, user, |records| records.employee_number = number)
            }
        }
    }

    /// Records `manager` as `user`'s manager, once they are an account of
    /// the same tenant.
    async fn set_manager(
        &self,
        acting: &Acting<'_>,
        user: &mut User<ResolvedTenant>,
        manager: Setting<UserId>,
    ) -> Result<(), AppError> {
        ensure_manager_known(self.ports.user_store.as_ref(), acting.tenant, &manager).await?;
        update_records(acting, user, |records| records.manager = manager)
    }

    /// Moves `user` onto `email`, unverified, or does nothing when it
    /// already has it.
    async fn change_email(
        &self,
        acting: &Acting<'_>,
        user: &mut User<ResolvedTenant>,
        email: Email,
    ) -> Result<(), AppError> {
        if user.email() == &email {
            return Ok(());
        }
        ensure_email_free(self.ports.user_store.as_ref(), acting.tenant, &email).await?;
        user.change_email(email, &acting.control)
            .map_err(AppError::from_domain)
    }

    /// When the changes moved `user` off `before`: ends the password resets
    /// mailed to the old address, and mails the link confirming the new
    /// one.
    async fn renew_email_links(
        &self,
        tenant: &ScopedTenant,
        user: &mut User<ResolvedTenant>,
        before: &Email,
    ) -> Result<(), AppError> {
        if user.email() == before {
            return Ok(());
        }
        self.ports
            .reset_requests
            .expire_pending_for_user(tenant, user.id())
            .await
            .or_internal()?;
        self.mail_confirmation(tenant, user).await
    }

    /// Mails `user` the link that confirms their address, while it is
    /// unproven.
    async fn mail_confirmation(
        &self,
        tenant: &ScopedTenant,
        user: &mut User<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let mail = ConfirmationMail {
            links: &self.ports.verification_links,
            scopes: &self.ports.link_scopes,
        };
        confirmation_mailed(mail, tenant, user).await
    }

    /// Saves `user` after its changes, ends the grants of an account they
    /// shut out and moves its links to a new address, and gives back what
    /// the change raised followed by the grants revoked.
    async fn kept(
        &self,
        tenant: &ScopedTenant,
        user: &mut User<ResolvedTenant>,
        from: UserStatus,
        before: &Email,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let revoked = self.cut_off_when_shut_out(tenant, user, from).await?;
        self.ports
            .user_store
            .save(tenant, user)
            .await
            .or_internal()?;
        self.renew_email_links(tenant, user, before).await?;
        if user.email() == before && was_let_in(from, user) {
            self.mail_confirmation(tenant, user).await?;
        }
        user.close_directory_change();
        let mut events = user.take_events(tenant);
        events.extend(revoked);
        Ok(events)
    }

    /// Ends what `user` does when the changes shut them out, returning the
    /// revocations to record.
    async fn cut_off_when_shut_out(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        from: UserStatus,
    ) -> Result<Vec<DomainEvent>, AppError> {
        if !from.can_authenticate() || user.can_authenticate() {
            return Ok(Vec::new());
        }
        self.ports
            .removal
            .cut_off(tenant, user, &ActorRef::System)
            .await
    }
}

impl Command for UpdateScimUseCase {
    type Caller = ScimCaller;
    type Input = UpdateScimRequest;
    type Output = Result<User<ResolvedTenant>, AppError>;

    /// Applies `request.changes` to the user, in order, ends the password
    /// resets mailed to an address they left, mails a link to confirm a new
    /// address or one still unproven on an account let back in, records each change by the system, `identity.verification_email_sent` once the mailer took the
    /// link, and the sync.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for missing/noncurrent directory tokens or disabled SCIM; `NotFound` for missing tenant user/manager/tenant/organization.
    /// - `AppError::Forbidden` for activating/moving an account with built-in permissions; `Conflict` for a taken address or removal of the last administrator.
    /// - `AppError::Domain` for a refused status transition or self-management; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &ScimCaller,
        auditor: &RequestAuditor,
        request: UpdateScimRequest,
    ) -> Result<User<ResolvedTenant>, AppError> {
        let UpdateScimRequest { user_id, changes } = request;
        let tenant = caller.tenant();
        let endpoint = self.ports.scim_authorities.endpoint(caller).await?;
        let mut user = existing_user(self.ports.user_store.as_ref(), tenant, &user_id).await?;
        let records = self.ports.access_records.as_ref();
        let control = directory_reach(records, tenant, &endpoint, &user_id)
            .await?
            .control;
        let acting = Acting {
            tenant,
            endpoint: &endpoint,
            control,
        };
        let (from, before) = (user.status(), user.email().clone());
        self.all_applied(&acting, &mut user, changes).await?;

        let events = self.kept(tenant, &mut user, from, &before).await?;
        record_synced(
            self.ports.scim_store.as_ref(),
            tenant,
            endpoint,
            auditor,
            events,
        )
        .await?;
        Ok(user)
    }
}

/// Refuses a manager who is not an account of `tenant`. Naming none
/// passes.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such account.
/// - `AppError::Internal` on storage failure.
pub(super) async fn ensure_manager_known(
    users: &dyn UserStore,
    tenant: &ScopedTenant,
    manager: &Setting<UserId>,
) -> Result<(), AppError> {
    let Setting::Set(manager) = manager else {
        return Ok(());
    };
    existing_user(users, tenant, manager).await.map(drop)
}

/// Renames `user`, or does nothing when the name is the same.
fn rename(
    acting: &Acting<'_>,
    user: &mut User<ResolvedTenant>,
    name: DisplayName,
) -> Result<(), AppError> {
    if user.display_name() == &name {
        return Ok(());
    }
    user.rename(name, acting.endpoint)
        .map_err(AppError::from_domain)
}

/// Makes `change` to `user`'s personal details, as the directory edits a
/// profile. Saving the details they have changes nothing.
fn update_details(
    acting: &Acting<'_>,
    user: &mut User<ResolvedTenant>,
    change: impl FnOnce(&mut PersonalDetails),
) -> Result<(), AppError> {
    let mut details = user.profile().details.clone();
    change(&mut details);
    user.update_details(details, acting.endpoint)
        .map_err(AppError::from_domain)
}

/// Makes `change` to what the directory records about `user`, as the
/// domain lets the directory keep its records. Saving the records they
/// have changes nothing.
fn update_records(
    acting: &Acting<'_>,
    user: &mut User<ResolvedTenant>,
    change: impl FnOnce(&mut DirectoryRecords),
) -> Result<(), AppError> {
    let mut records = user.profile().records.clone();
    change(&mut records);
    user.update_records(records, &acting.control)
        .map_err(AppError::from_domain)
}

/// Whether the changes let `user`, who could not sign in at `from`, back
/// in.
fn was_let_in(from: UserStatus, user: &User<ResolvedTenant>) -> bool {
    !from.can_authenticate() && user.can_authenticate()
}

/// How the domain switches an account the directory turns on or off.
///
/// An active account is locked; a locked or switched-off one is let back
/// in. One still waiting on its invitation or its address is switched off,
/// so following the link later does not let it in. One closing for an
/// erasure signs nobody in already and is left as it is.
fn directory_switch(switch: AccountSwitch) -> DirectorySwitch {
    match switch {
        AccountSwitch::On => DirectorySwitch::LetIn,
        AccountSwitch::Off => DirectorySwitch::ShutOut,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::identity::account::profile_values::{
        Department, ExternalId, GivenName,
    };
    use ianua_domain::shared::config::DisplayNameLimits;
    use ianua_domain::types::{PrincipalRef, SessionId, TenantId};

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::agents::FakeDelegationStore;
    use crate::test_support::authentication::{
        FakeResetRequestStore, FakeSessionStore, password_session,
    };
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_role,
    };
    use crate::test_support::identity::{
        FakeTokenStore, FakeUserStore, removal_over, stored_user, verification_links_over,
    };
    use crate::test_support::scim::{SignInRefusal, refused_sign_in, scim_caller, signed_in};
    use crate::test_support::{FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_ctx};

    struct Acme {
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        ada: UserId,
        laptop: SessionId,
    }

    fn acme_with(status: UserStatus) -> Acme {
        let ada = UserId::new();
        let users = Arc::new(FakeUserStore::empty());
        users.add(stored_user(ada, "ada@acme.com", status));
        let laptop = password_session(ada, "adas-laptop", SecondFactor::NotOwed);
        Acme {
            users,
            laptop: *laptop.id(),
            sessions: Arc::new(FakeSessionStore::with_session(laptop)),
            ada,
        }
    }

    impl Acme {
        fn ports(&self) -> UpdateScimPorts {
            UpdateScimPorts {
                scim_authorities: signed_in(),
                user_store: self.users.clone(),
                removal: removal_over(&self.sessions, &Arc::new(FakeDelegationStore::empty())),
                ..UpdateScimPorts::fakes()
            }
        }

        fn update(
            &self,
            ports: UpdateScimPorts,
            changes: Vec<ScimUserChange>,
        ) -> Result<User<ResolvedTenant>, AppError> {
            let use_case = UpdateScimUseCase::new(ports);
            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            let request = UpdateScimRequest {
                user_id: self.ada,
                changes,
            };
            block_on(use_case.execute(&scim_caller(), &auditor, request))
        }

        fn switch(&self, switch: AccountSwitch) -> Result<User<ResolvedTenant>, AppError> {
            self.update(self.ports(), vec![ScimUserChange::Active(switch)])
        }

        fn status(&self) -> UserStatus {
            self.users.get_status(&self.ada).unwrap()
        }

        fn ada_holding_everything(&self) -> FakeAccessRecordStore {
            let owner = stored_role("Owner", SystemPermission::all().to_vec(), Vec::new());
            let held = stored_assignment(PrincipalRef::User(self.ada), *owner.id());
            FakeAccessRecordStore::holding(
                test_ctx().tenant_id(),
                AccessRecords {
                    roles: vec![owner],
                    assignments: vec![held],
                    groups: Vec::new(),
                    memberships: Vec::new(),
                    catalogue: Vec::new(),
                    break_glass: Vec::new(),
                },
            )
        }
    }

    fn address(email: &str) -> ScimUserChange {
        ScimUserChange::UserName(Email::new(email).unwrap())
    }

    /// Okta switches Ada off the day she leaves. She is locked, and her
    /// sessions end.
    #[test]
    fn switching_a_user_off_locks_them_and_ends_their_sessions() {
        let acme = acme_with(UserStatus::Active);

        acme.switch(AccountSwitch::Off).unwrap();

        assert_eq!(acme.status(), UserStatus::Locked);
        assert_eq!(
            acme.sessions.get_status(&acme.laptop),
            Some(SessionStatus::Revoked)
        );
    }

    /// Switching off an invited user or one awaiting email verification
    /// leaves the account deactivated.
    #[test]
    fn switching_off_a_user_still_waiting_to_join_shuts_them_out() {
        for waiting in [UserStatus::Invited, UserStatus::PendingVerification] {
            let acme = acme_with(waiting);

            acme.switch(AccountSwitch::Off).unwrap();

            assert_eq!(acme.status(), UserStatus::Deactivated, "{waiting:?}");
        }
    }

    /// Okta switches Ada back on after her leave. She can sign in again.
    #[test]
    fn switching_a_locked_user_back_on_restores_them() {
        let acme = acme_with(UserStatus::Locked);

        acme.switch(AccountSwitch::On).unwrap();

        assert_eq!(acme.status(), UserStatus::Active);
    }

    /// Okta re-hires Ada, whom it removed last year. Her switched-off
    /// account is let back in, keeping its history.
    #[test]
    fn switching_a_removed_user_back_on_lets_them_in() {
        let acme = acme_with(UserStatus::Deactivated);

        acme.switch(AccountSwitch::On).unwrap();

        assert_eq!(acme.status(), UserStatus::Active);
    }

    /// Okta renames Ada after she marries. Her profile shows the new name.
    #[test]
    fn a_user_is_renamed() {
        let acme = acme_with(UserStatus::Active);
        let name = DisplayName::new("Ada King", &DisplayNameLimits::default()).unwrap();

        let user = acme
            .update(acme.ports(), vec![ScimUserChange::DisplayName(name)])
            .unwrap();

        assert_eq!(user.display_name().as_str(), "Ada King");
    }

    /// Okta moves Ada to a new address. The address is hers now, and waits
    /// for her to confirm it.
    #[test]
    fn a_new_address_waits_for_its_holder_to_confirm_it() {
        let acme = acme_with(UserStatus::Active);

        let user = acme
            .update(acme.ports(), vec![address("ada.king@acme.com")])
            .unwrap();

        assert_eq!(user.email().as_str(), "ada.king@acme.com");
        assert!(!user.email_verified());
    }

    /// `ports`, mailing through `mailer`.
    fn mailing_to(mailer: &Arc<FakeMailer>, ports: UpdateScimPorts) -> UpdateScimPorts {
        UpdateScimPorts {
            verification_links: verification_links_over(&Arc::new(FakeTokenStore::empty()), mailer),
            ..ports
        }
    }

    /// Okta moves Ada to a new address. A link to confirm it goes to the
    /// new address.
    #[test]
    fn a_new_unproven_address_is_mailed_a_confirmation_link() {
        let acme = acme_with(UserStatus::Active);
        let mailer = Arc::new(FakeMailer::new());

        acme.update(
            mailing_to(&mailer, acme.ports()),
            vec![address("ada.king@acme.com")],
        )
        .unwrap();

        assert_eq!(mailer.recipients(), ["ada.king@acme.com"]);
    }

    /// Okta opened Ada switched off, so no link went out. Letting her in
    /// mails her the link that confirms her address.
    #[test]
    fn an_account_let_in_with_an_unproven_address_is_mailed_a_link() {
        let acme = acme_with(UserStatus::PendingVerification);
        acme.switch(AccountSwitch::Off).unwrap();
        let mailer = Arc::new(FakeMailer::new());

        acme.update(
            mailing_to(&mailer, acme.ports()),
            vec![ScimUserChange::Active(AccountSwitch::On)],
        )
        .unwrap();

        assert_eq!(acme.status(), UserStatus::Active);
        assert_eq!(mailer.recipients(), ["ada@acme.com"]);
    }

    /// Ada's address was proven before Okta locked her. Letting her back
    /// in mails nothing.
    #[test]
    fn an_account_let_back_in_with_a_proven_address_is_mailed_nothing() {
        let acme = acme_with(UserStatus::Locked);
        let mailer = Arc::new(FakeMailer::new());

        acme.update(
            mailing_to(&mailer, acme.ports()),
            vec![ScimUserChange::Active(AccountSwitch::On)],
        )
        .unwrap();

        assert!(mailer.recipients().is_empty());
    }

    /// Okta lets Ada in and moves her in one request. One link goes out,
    /// to the new address.
    #[test]
    fn an_account_let_in_and_moved_at_once_is_mailed_one_link() {
        let acme = acme_with(UserStatus::PendingVerification);
        acme.switch(AccountSwitch::Off).unwrap();
        let mailer = Arc::new(FakeMailer::new());

        acme.update(
            mailing_to(&mailer, acme.ports()),
            vec![
                address("ada.king@acme.com"),
                ScimUserChange::Active(AccountSwitch::On),
            ],
        )
        .unwrap();

        assert_eq!(mailer.recipients(), ["ada.king@acme.com"]);
    }

    /// Okta moves Ada to a new address. The password resets mailed to her
    /// old one stop working, so whoever reads that mailbox now cannot use
    /// them.
    #[test]
    fn resets_mailed_to_the_old_address_are_ended() {
        let acme = acme_with(UserStatus::Active);
        let resets = Arc::new(FakeResetRequestStore::empty());
        let ports = UpdateScimPorts {
            reset_requests: resets.clone(),
            ..acme.ports()
        };

        acme.update(ports, vec![address("ada.king@acme.com")])
            .unwrap();

        assert_eq!(resets.superseded(), [acme.ada]);
    }

    /// Okta sends Ada's record again with the address she already has.
    /// Nothing moved, so no link is mailed.
    #[test]
    fn an_unchanged_address_is_mailed_nothing() {
        let acme = acme_with(UserStatus::Active);
        let mailer = Arc::new(FakeMailer::new());

        acme.update(
            mailing_to(&mailer, acme.ports()),
            vec![address("ada@acme.com")],
        )
        .unwrap();

        assert_eq!(mailer.count(), 0);
    }

    /// Okta moves Ada onto Grace's address. It is taken, and Ada keeps hers.
    #[test]
    fn a_new_address_already_in_use_is_a_conflict() {
        let acme = acme_with(UserStatus::Active);
        acme.users.add_active_user(UserId::new(), "grace@acme.com");

        let result = acme.update(acme.ports(), vec![address("grace@acme.com")]);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(
            acme.users.get_email(&acme.ada).unwrap().as_str(),
            "ada@acme.com"
        );
    }

    /// Moving an owner's email address through SCIM is forbidden, and the
    /// stored address remains unchanged.
    #[test]
    fn the_directory_never_moves_an_account_holding_built_in_permissions() {
        let acme = acme_with(UserStatus::Active);
        let ports = UpdateScimPorts {
            access_records: Arc::new(acme.ada_holding_everything()),
            ..acme.ports()
        };

        let result = acme.update(ports, vec![address("mallory@evil.test")]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            acme.users.get_email(&acme.ada).unwrap().as_str(),
            "ada@acme.com"
        );
    }

    /// Switching off the last administrator returns a conflict and leaves
    /// that administrator active.
    #[test]
    fn the_directory_never_shuts_out_the_last_administrator() {
        let acme = acme_with(UserStatus::Active);
        let ports = UpdateScimPorts {
            access_records: Arc::new(acme.ada_holding_everything()),
            ..acme.ports()
        };

        let result = acme.update(ports, vec![ScimUserChange::Active(AccountSwitch::Off)]);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(acme.status(), UserStatus::Active);
    }

    /// Switching off another tenant's user returns not found and leaves
    /// that user's account active.
    #[test]
    fn a_user_of_another_tenant_is_not_found() {
        let acme = acme_with(UserStatus::Active);
        let alan = UserId::new();
        let globex = TenantId::new();
        acme.users.add_in(
            globex,
            stored_user(alan, "alan@globex.com", UserStatus::Active),
        );
        let use_case = UpdateScimUseCase::new(acme.ports());
        let request = UpdateScimRequest {
            user_id: alan,
            changes: vec![ScimUserChange::Active(AccountSwitch::Off)],
        };

        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let result = block_on(use_case.execute(&scim_caller(), &auditor, request));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        let globex_alan = block_on(
            acme.users
                .find_by_id(&ScopedTenant::for_test(globex), &alan),
        );
        assert_eq!(globex_alan.unwrap().unwrap().status(), UserStatus::Active);
    }

    /// Missing, invalid or rotated tokens and disabled SCIM each return an
    /// unauthenticated error and leave the user's account active.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let acme = acme_with(UserStatus::Active);
            let (scim_authorities, caller) = refused_sign_in(refusal);
            let use_case = UpdateScimUseCase::new(UpdateScimPorts {
                scim_authorities,
                ..acme.ports()
            });
            let request = UpdateScimRequest {
                user_id: acme.ada,
                changes: vec![ScimUserChange::Active(AccountSwitch::Off)],
            };

            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            let result = block_on(use_case.execute(&caller, &auditor, request));

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
            assert_eq!(acme.status(), UserStatus::Active);
        }
    }

    /// Entra sends Ada's given name, its id for her, her department and
    /// Grace as her manager. Her profile holds each of them.
    #[test]
    fn the_directory_fills_names_and_its_records() {
        let acme = acme_with(UserStatus::Active);
        let grace = UserId::new();
        acme.users
            .add(stored_user(grace, "grace@acme.com", UserStatus::Active));
        let changes = vec![
            ScimUserChange::GivenName(Setting::Set(GivenName::new("Ada").unwrap())),
            ScimUserChange::ExternalId(Setting::Set(ExternalId::new("00u-ada").unwrap())),
            ScimUserChange::Department(Setting::Set(Department::new("Research").unwrap())),
            ScimUserChange::Manager(Setting::Set(grace)),
        ];

        let ada = acme.update(acme.ports(), changes).unwrap();

        let profile = ada.profile();
        assert_eq!(profile.details.given_name.value().unwrap().as_str(), "Ada");
        assert_eq!(
            profile.records.external_id.value().unwrap().as_str(),
            "00u-ada"
        );
        assert_eq!(profile.records.manager, Setting::Set(grace));
    }

    /// Entra names a manager Acme has no account for. It is not found, and
    /// Ada's records stay as they were.
    #[test]
    fn a_manager_outside_the_tenant_is_not_found() {
        let acme = acme_with(UserStatus::Active);
        let changes = vec![ScimUserChange::Manager(Setting::Set(UserId::new()))];

        let result = acme.update(acme.ports(), changes);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Naming a user as their own manager returns a domain error.
    #[test]
    fn nobody_is_made_their_own_manager() {
        let acme = acme_with(UserStatus::Active);
        let changes = vec![ScimUserChange::Manager(Setting::Set(acme.ada))];

        let result = acme.update(acme.ports(), changes);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }
}
