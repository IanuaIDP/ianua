//! Reset a tenant user's password: an admin supplies a new one or has one
//! generated, and the user is signed out everywhere.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::breach::NewPasswordBreach;
use ianua_domain::domains::identity::account::admin_password_reset::AdminPasswordReset;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PasswordHash, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CredentialStore;
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::new_password::{
    Earlier, NewPassword, NewPasswordPorts, current_hash,
};
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authentication::password_rules;
use crate::services::lookup::{existing_tenant, existing_user};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::users::credentials::new_password::{MadePassword, PasswordMaker};
use crate::use_cases::identity::users::sessions::sign_out::sign_out_everywhere;

/// The password a reset set, shown once to the admin and never stored in
/// plain text.
pub struct ResetPasswordResult {
    /// The raw replacement secret returned to the administrator once.
    pub new_password: Secret,
    /// What the breach check found of it, so an admin whose tenant only
    /// warns is told.
    pub breach: NewPasswordBreach,
}

/// Whose password to reset, and to what.
pub struct ResetPasswordRequest {
    /// The user whose password is reset.
    pub user_id: UserId,
    /// The password to set, or `None` to generate one.
    pub new_password: Option<String>,
}

/// The ports [`ResetPasswordUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetPasswordPorts {
    /// Loads and saves users.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Writes the user's password hash.
    pub credential_store: Arc<dyn CredentialStore>,
    /// Reads the tenant's password rules.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Revokes the user's sessions.
    pub session_store: Arc<dyn SessionStore>,
    /// Checks or draws the new password, and hashes it.
    pub passwords: Arc<PasswordMaker>,
    /// Checks the new password against the account's recent ones, under the
    /// node's cap on hashes running at once.
    pub hashing: PasswordHashing,
    /// Checks the new password against breaches, the common list and the
    /// account's recent passwords, and keeps the old one among them.
    pub new_password: NewPasswordPorts,
}

/// Resets the password of a user of the caller's tenant.
pub struct ResetPasswordUseCase {
    ports: ResetPasswordPorts,
}

impl ResetPasswordUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResetPasswordPorts) -> Self {
        Self { ports }
    }

    /// Retires the account's old password and writes `hash` as the password
    /// of the account `leave` was given for.
    async fn install(
        &self,
        tenant: &ScopedTenant,
        leave: &AdminPasswordReset<ResolvedTenant>,
        vetted: &VettedPassword,
    ) -> Result<(), AppError> {
        self.ports
            .new_password
            .retire(tenant, leave.user_id(), vetted.replaced.as_ref())
            .await?;
        self.ports
            .credential_store
            .reset_password_hash(tenant, leave, &vetted.hash)
            .await
            .or_internal()
    }

    /// What the checks beyond length and characters make of `made` for
    /// `user`: refused for the person's name or address, a common password,
    /// a recent one or a breach the tenant blocks; otherwise what the breach
    /// check found, with the hash it replaces.
    async fn vetted(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        made: &MadePassword,
    ) -> Result<VettedPassword, AppError> {
        let workspace = existing_tenant(self.ports.tenant_store.as_ref(), tenant).await?;
        let new = NewPassword {
            tenant,
            account: user,
            chosen: &made.secret,
        };
        let checks = &self.ports.new_password;
        let breach = checks.screened(&workspace, new).await?;
        let replaced = current_hash(self.ports.credential_store.as_ref(), new).await?;
        let earlier = Earlier {
            current: replaced.as_ref(),
            hashing: &self.ports.hashing,
        };
        checks.ensure_not_repeated(&workspace, new, earlier).await?;
        Ok(VettedPassword {
            hash: made.hash.clone(),
            breach,
            replaced,
        })
    }

    /// Ends every session `user_id` holds.
    async fn sign_out(&self, tenant: &ScopedTenant, user_id: &UserId) -> Result<(), AppError> {
        sign_out_everywhere(self.ports.session_store.as_ref(), tenant, user_id).await
    }

    /// The supplied password once it meets the tenant's policy, or a freshly
    /// generated one that does.
    async fn password_to_set(
        &self,
        tenant: &ScopedTenant,
        supplied: Option<String>,
    ) -> Result<MadePassword, AppError> {
        let policy = password_rules::for_tenant(self.ports.tenant_store.as_ref(), tenant).await?;
        self.ports.passwords.made(&policy, supplied).await
    }
}

impl Command for ResetPasswordUseCase {
    type Caller = CallerContext;
    type Input = ResetPasswordRequest;
    type Output = Result<ResetPasswordResult, AppError>;

    /// Sets a new password on `request.user_id`. A supplied password must
    /// meet the tenant's policy; `None` generates one that does. Every
    /// session the user holds is revoked, and devices they remembered stop
    /// skipping the second factor.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing user.
    /// - `AppError::Forbidden` without sign-in-change rights or when the user holds more rights; `Conflict` for a deactivated user.
    /// - `AppError::Domain` for a supplied password outside policy; `Busy` when hashing cannot start in time.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ResetPasswordRequest,
    ) -> Result<ResetPasswordResult, AppError> {
        let ResetPasswordRequest {
            user_id,
            new_password,
        } = request;
        let tenant = ctx.tenant();
        let users = self.ports.user_store.as_ref();
        let records = self.ports.access_records.as_ref();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let signing_in = AccountAction::ChangeSignIn;
        let control = account_control(records, &tenant, &authority, &user_id, signing_in).await?;
        let mut user = existing_user(users, &tenant, &user_id).await?;
        let made = self.password_to_set(&tenant, new_password).await?;
        let vetted = self.vetted(&tenant, &user, &made).await?;
        let leave = user.allow_password_reset(&control);
        let leave = leave.map_err(AppError::from_domain)?;

        self.install(&tenant, &leave, &vetted).await?;
        users.save(&tenant, &user).await.or_internal()?;
        self.sign_out(&tenant, &user_id).await?;
        auditor
            .dispatch_by(&ctx.actor(), user.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(ResetPasswordResult {
            new_password: made.secret,
            breach: vetted.breach,
        })
    }
}

/// A new password, checked: its hash, what the breach check found, and the
/// hash it replaces.
struct VettedPassword {
    /// What is stored.
    hash: PasswordHash,
    /// What the breach check found.
    breach: NewPasswordBreach,
    /// The account's password before, kept among its retired ones.
    replaced: Option<PasswordHash>,
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::{CharacterRequirements, PasswordPolicy};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeSessionStore;
    use crate::test_support::identity::{
        FakeUserStore, RecordingCredentialStore, access_where_holds,
    };
    use crate::test_support::tenant::{
        FakeTenantStore, tenant_store_with_password_policy, test_tenant_for_ctx,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Alice, a user, and the stores that watch her password and sessions.
    struct Tenant {
        alice: UserId,
        credentials: Arc<RecordingCredentialStore>,
        sessions: Arc<FakeSessionStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tenant {
        fn with_alice() -> Self {
            Self {
                alice: UserId::new(),
                credentials: Arc::new(RecordingCredentialStore::default()),
                sessions: Arc::new(FakeSessionStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> ResetPasswordPorts {
            ResetPasswordPorts {
                user_store: Arc::new(FakeUserStore::with_user(self.alice, "alice@acme.com")),
                credential_store: self.credentials.clone(),
                tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                session_store: self.sessions.clone(),
                ..ResetPasswordPorts::fakes()
            }
        }

        fn reset(
            &self,
            ports: ResetPasswordPorts,
            new_password: Option<&str>,
        ) -> Result<ResetPasswordResult, AppError> {
            let use_case = ResetPasswordUseCase::new(ports);
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                ResetPasswordRequest {
                    user_id: self.alice,
                    new_password: new_password.map(str::to_owned),
                },
            ))
        }
    }

    fn requiring(min_length: u8) -> PasswordPolicy {
        PasswordPolicy::new(min_length, CharacterRequirements::strict()).unwrap()
    }

    /// Ann resets Alice's password without naming one. A password is made
    /// and stored, Alice is signed out and the reset is recorded.
    #[test]
    fn a_reset_sets_a_generated_password_and_signs_the_user_out() {
        let tenant = Tenant::with_alice();

        let result = tenant.reset(tenant.ports(), None).unwrap();

        assert!(!result.new_password.expose().is_empty());
        assert!(tenant.credentials.hash_of(&tenant.alice).is_some());
        assert_eq!(*tenant.sessions.revoke_all_count.lock().unwrap(), 1);
        assert_eq!(
            tenant.sink.records.lock().unwrap()[0],
            "identity.password_reset"
        );
    }

    /// Ann resets the password of a user the tenant does not have. It is
    /// not found and nothing is recorded.
    #[test]
    fn an_unknown_user_is_not_found() {
        let tenant = Tenant::with_alice();
        let ports = ResetPasswordPorts {
            user_store: Arc::new(FakeUserStore::empty()),
            ..tenant.ports()
        };

        let result = tenant.reset(ports, None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(tenant.sink.records.lock().unwrap().is_empty());
    }

    /// The tenant asks for 20 characters, and Ann sets 15. It is refused
    /// and nothing is stored.
    #[test]
    fn a_supplied_password_is_held_to_the_tenants_policy() {
        let tenant = Tenant::with_alice();
        let ports = ResetPasswordPorts {
            tenant_store: tenant_store_with_password_policy(requiring(20)),
            ..tenant.ports()
        };

        let result = tenant.reset(ports, Some("Fifteen1Chars!!"));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(tenant.credentials.hash_of(&tenant.alice).is_none());
    }

    /// The tenant asks for 24 characters. The password made for Alice meets
    /// that.
    #[test]
    fn a_generated_password_meets_the_tenants_policy() {
        let tenant = Tenant::with_alice();
        let ports = ResetPasswordPorts {
            tenant_store: tenant_store_with_password_policy(requiring(24)),
            ..tenant.ports()
        };

        let result = tenant.reset(ports, None).unwrap();

        assert!(requiring(24).validate(result.new_password.expose()).is_ok());
    }

    /// User-viewing rights do not permit resetting Alice's password.
    /// No replacement hash is stored.
    #[test]
    fn a_caller_who_may_not_change_sign_ins_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = ResetPasswordPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..tenant.ports()
        };

        let result = tenant.reset(ports, None);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.credentials.hash_of(&tenant.alice).is_none());
    }

    /// User-update rights do not permit resetting Alice's password while
    /// she holds broader user-management rights. No replacement hash is stored.
    #[test]
    fn a_user_holding_more_than_the_caller_keeps_their_password() {
        let tenant = Tenant::with_alice();
        let ports = ResetPasswordPorts {
            access_records: access_where_holds(tenant.alice, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..tenant.ports()
        };

        let result = tenant.reset(ports, None);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.credentials.hash_of(&tenant.alice).is_none());
    }

    /// A signed-out caller cannot reset Alice's password.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = ResetPasswordPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.reset(ports, None);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
