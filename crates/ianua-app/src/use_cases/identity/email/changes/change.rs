//! Change email: an admin moves a user onto a new address at once. The new
//! address is unconfirmed, and a link goes to it.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::granter::AccountControl;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Email, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::ResetRequestStore;
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::ports::limits::{MailPurpose, MailThrottle};
use crate::services::identity::address_free::ensure_email_free;
use crate::services::limits::mail_cooldown::ensure_mail_admitted;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::email::{LinkMailed, VerificationLinks};

/// The ports [`ChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangePorts {
    /// Loads and saves users, and finds addresses already taken.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Ends the password resets mailed to the old address.
    pub reset_requests: Arc<dyn ResetRequestStore>,
    /// Mails the link that confirms the new address.
    pub verification_links: Arc<VerificationLinks>,
    /// Lets one confirmation link a minute through to an address.
    pub mail_throttle: Arc<dyn MailThrottle>,
}

/// Which user gets which new address.
pub struct ChangeRequest {
    /// The user whose address changes.
    pub user_id: UserId,
    /// The address they get.
    pub new_email: Email,
    /// Where the confirmation link lands.
    pub scope: LinkScope,
}

/// Moves a user of the caller's tenant onto a new address.
pub struct ChangeUseCase {
    ports: ChangePorts,
}

impl ChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangePorts) -> Self {
        Self { ports }
    }

    /// `authority` acting on `user_id`'s sign-in, refused before the user
    /// is read when the caller may not change sign-ins.
    async fn sign_in_control<'a>(
        &self,
        tenant: &ScopedTenant,
        authority: &'a TenantAuthority,
        user_id: &UserId,
    ) -> Result<AccountControl<'a>, AppError> {
        let records = self.ports.access_records.as_ref();
        let signing_in = AccountAction::ChangeSignIn;
        account_control(records, tenant, authority, user_id, signing_in).await
    }

    /// Ends the password resets mailed to the address `user` left, and mails
    /// a link to confirm the one they have now.
    async fn relinked(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        scope: &LinkScope,
    ) -> Result<LinkMailed, AppError> {
        self.ports
            .reset_requests
            .expire_pending_for_user(tenant, user.id())
            .await
            .or_internal()?;
        self.ports
            .verification_links
            .send(tenant, user, scope)
            .await
    }
}

impl Command for ChangeUseCase {
    type Caller = CallerContext;
    type Input = ChangeRequest;
    type Output = Result<(), AppError>;

    /// Gives `request.user_id` the address `request.new_email` at once.
    ///
    /// Nobody vouches for an address: it is unconfirmed until its holder
    /// follows the link mailed to it. Every link mailed to the old address,
    /// for confirming it or resetting the password, stops working. Asking
    /// for the address the user already has changes nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing user.
    /// - `AppError::Forbidden` without sign-in-change rights or when the user holds more rights.
    /// - `AppError::Conflict` for a taken address; `TooManyRequests` for a confirmation sent within a minute.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeRequest,
    ) -> Result<(), AppError> {
        let ChangeRequest {
            user_id,
            new_email,
            scope,
        } = request;
        let tenant = ctx.tenant();
        let users = self.ports.user_store.as_ref();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = self.sign_in_control(&tenant, &authority, &user_id).await?;
        let mut user = existing_user(users, &tenant, &user_id).await?;
        if *user.email() == new_email {
            return Ok(());
        }
        ensure_email_free(users, &tenant, &new_email).await?;
        let changed = user.change_email(new_email, &control);
        changed.map_err(AppError::from_domain)?;
        let throttle = self.ports.mail_throttle.as_ref();
        ensure_mail_admitted(throttle, MailPurpose::AddressConfirmation, user.email()).await?;

        users.save(&tenant, &user).await.or_internal()?;
        let mailed = self.relinked(&tenant, &user, &scope).await?;
        mailed.note_on(&mut user);
        auditor
            .dispatch_by(&ctx.actor(), user.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeResetRequestStore;
    use crate::test_support::identity::{
        FakeTokenStore, FakeUserStore, access_where_holds, verification_links_over,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_ctx, test_link_scope,
    };

    /// Alice at alice@acme.com, and the stores that watch her address.
    struct Tenant {
        alice: UserId,
        users: Arc<FakeUserStore>,
        resets: Arc<FakeResetRequestStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tenant {
        fn with_alice() -> Self {
            let alice = UserId::new();
            Self {
                alice,
                users: Arc::new(FakeUserStore::with_user(alice, "alice@acme.com")),
                resets: Arc::new(FakeResetRequestStore::empty()),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> ChangePorts {
            ChangePorts {
                user_store: self.users.clone(),
                reset_requests: self.resets.clone(),
                verification_links: verification_links_over(
                    &Arc::new(FakeTokenStore::empty()),
                    &self.mailer,
                ),
                ..ChangePorts::fakes()
            }
        }

        fn change(&self, ports: ChangePorts, to: &str) -> Result<(), AppError> {
            block_on(ChangeUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                ChangeRequest {
                    user_id: self.alice,
                    new_email: Email::new(to).unwrap(),
                    scope: test_link_scope(),
                },
            ))
        }

        fn alice(&self) -> User<ResolvedTenant> {
            block_on(self.users.find_by_id(&test_ctx().tenant(), &self.alice))
                .unwrap()
                .unwrap()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann moves Alice to new@acme.com. Alice has the new address at once,
    /// unconfirmed, a link to confirm it goes there, and the change is
    /// recorded.
    #[test]
    fn the_address_changes_at_once_and_unconfirmed() {
        let tenant = Tenant::with_alice();

        tenant.change(tenant.ports(), "new@acme.com").unwrap();

        let alice = tenant.alice();
        assert_eq!(alice.email().as_str(), "new@acme.com");
        assert!(!alice.email_verified());
        assert_eq!(tenant.mailer.recipients(), ["new@acme.com"]);
        assert_eq!(tenant.records()[0], "identity.email_changed");
    }

    /// Ann moves Alice. The password resets mailed to the old address stop
    /// working.
    #[test]
    fn resets_mailed_to_the_old_address_are_ended() {
        let tenant = Tenant::with_alice();

        tenant.change(tenant.ports(), "new@acme.com").unwrap();

        assert_eq!(tenant.resets.superseded(), [tenant.alice]);
    }

    /// Ann gives Alice the address she already has. Nothing changes, is
    /// mailed or recorded.
    #[test]
    fn the_same_address_changes_nothing() {
        let tenant = Tenant::with_alice();

        tenant.change(tenant.ports(), "alice@acme.com").unwrap();

        assert!(tenant.alice().email_verified());
        assert_eq!(tenant.mailer.count(), 0);
        assert!(tenant.records().is_empty());
    }

    /// Ann moves Alice to Bob's address. It is a conflict, and nothing is
    /// recorded.
    #[test]
    fn a_taken_address_is_a_conflict() {
        let tenant = Tenant::with_alice();
        tenant.users.add_active_user(UserId::new(), "bob@acme.com");

        let result = tenant.change(tenant.ports(), "bob@acme.com");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.alice().email().as_str(), "alice@acme.com");
        assert!(tenant.records().is_empty());
    }

    /// Ann moves a user the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let tenant = Tenant::with_alice();
        let ports = ChangePorts {
            user_store: Arc::new(FakeUserStore::empty()),
            ..tenant.ports()
        };

        let result = tenant.change(ports, "new@acme.com");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// User-viewing rights do not permit changing Alice's sign-in address.
    /// The refused request leaves her original address intact.
    #[test]
    fn a_caller_who_may_not_change_sign_ins_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = ChangePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..tenant.ports()
        };

        let result = tenant.change(ports, "sam@evil.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.alice().email().as_str(), "alice@acme.com");
    }

    /// A user updater cannot change Alice's address while she holds broader
    /// user-management rights. Her original address stays intact.
    #[test]
    fn a_user_holding_more_than_the_caller_keeps_their_address() {
        let tenant = Tenant::with_alice();
        let ports = ChangePorts {
            access_records: access_where_holds(tenant.alice, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..tenant.ports()
        };

        let result = tenant.change(ports, "sam@evil.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.alice().email().as_str(), "alice@acme.com");
    }

    /// A signed-out caller cannot change Alice's email address.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = ChangePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.change(ports, "new@acme.com");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
