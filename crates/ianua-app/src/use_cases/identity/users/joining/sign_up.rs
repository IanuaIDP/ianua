//! Self sign-up: a person creates their own account in a tenant that allows
//! it.
//!
//! Off unless the tenant turns it on. The account starts unconfirmed and
//! cannot sign in until its owner follows the verification link mailed to
//! it, so an address someone typed on another person's behalf never becomes
//! a working account. An address that already has an account gets the same
//! answer as a new one: the form must not tell a stranger who is
//! registered.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::domains::tenant::access::self_sign_up::SelfSignUp;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, DisplayName, Email, UserId};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CredentialStore;
use crate::ports::authorization::{RoleAssignmentStore, RoleStore};
use crate::ports::identity::UserStore;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::channels::NO_SIGN_UPS;
use crate::services::authentication::new_password::{NewPassword, NewPasswordPorts};
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authorization::starting_roles::{self, RoleStores};
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::email::VerificationLinks;
use crate::use_cases::identity::users::joining::room::ensure_room;

/// What a person signing up gives.
pub struct SignUp {
    /// The address the account signs in with.
    pub email: Email,
    /// The name shown to other people in the tenant.
    pub display_name: DisplayName,
    /// The password they chose.
    pub password: String,
}

/// A sign-up, with the plan limits of the tenant it is made in and where
/// the confirmation link lands.
pub struct SignUpRequest {
    /// What the person gave.
    pub person: SignUp,
    /// The limits the new account counts against.
    pub limits: PlanLimits,
    /// Where the confirmation link lands.
    pub scope: LinkScope,
}

/// What came of a sign-up.
pub enum SignUpOutcome {
    /// A new, unconfirmed account; its owner was sent the verification link.
    Created(UserId),
    /// The address already has an account, so nothing was created.
    AlreadyRegistered,
}

/// The ports [`SignUpUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SignUpPorts {
    /// Reads whether the tenant takes sign-ups, and its password rules.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Saves the account.
    pub user_store: Arc<dyn UserStore>,
    /// Saves its password.
    pub credential_store: Arc<dyn CredentialStore>,
    /// Holds the tenant to its plan's user limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Reads the roles a new user starts with.
    pub role_store: Arc<dyn RoleStore>,
    /// Grants them.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// Mails the link that confirms the address.
    pub verification_links: Arc<VerificationLinks>,
    /// Hashes the password chosen, under the node's cap on hashes running
    /// at once.
    pub hashing: PasswordHashing,
    /// Checks the password against breaches and the common list.
    pub new_password: NewPasswordPorts,
}

/// Opens a person's own account in a tenant that takes sign-ups.
pub struct SignUpUseCase {
    ports: SignUpPorts,
}

impl SignUpUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SignUpPorts) -> Self {
        Self { ports }
    }

    /// The tenant's word that it takes sign-ups, once the password meets its
    /// rules for a new password.
    async fn admitted(
        &self,
        tenant: &ScopedTenant,
        password: &str,
    ) -> Result<SelfSignUp<ResolvedTenant>, AppError> {
        let found = existing_tenant(self.ports.tenant_store.as_ref(), tenant).await?;
        let scope = ResolvedTenant::new(*found.id(), found.slug().clone());
        let admitted = found
            .admits_self_sign_up(&scope)
            .map_err(AppError::from_domain)?;
        let Some(policy) = found.auth_config().new_password_policy() else {
            return Err(AppError::Forbidden(message!(
                "identity-this-workspace-signs-nobody-in-with",
                "this workspace signs nobody in with a password"
            )));
        };
        policy
            .validate(password)
            .map_err(|e| AppError::Domain(DomainError::Validation(e)))?;
        Ok(admitted)
    }

    /// Refuses `chosen` for `user` when it holds their name or address, is
    /// common, or is breached where the tenant blocks breached passwords.
    ///
    /// It runs before the address is looked up, so a taken address and a
    /// free one take the same checks and the same time. A warning the
    /// tenant gives for a breached password is logged, never answered: an
    /// answer only a new account gets would tell who is registered.
    async fn vet(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        chosen: &Secret,
    ) -> Result<(), AppError> {
        let workspace = existing_tenant(self.ports.tenant_store.as_ref(), tenant).await?;
        let new = NewPassword {
            tenant,
            account: user,
            chosen,
        };
        self.ports.new_password.screened(&workspace, new).await?;
        Ok(())
    }

    /// The answer for an address that already has an account, reached only
    /// after hashing `password` as a new account's is, under a permit like
    /// one, so the time taken does not tell who is registered.
    async fn already_registered(&self, password: &str) -> Result<SignUpOutcome, AppError> {
        let hasher = self.ports.hashing.permitted().await?;
        let _ = hasher.hash(password);
        Ok(SignUpOutcome::AlreadyRegistered)
    }

    /// Stores the unconfirmed account, its password and its starting roles.
    async fn store(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        password: &str,
    ) -> Result<(), AppError> {
        let hash = self
            .ports
            .hashing
            .permitted()
            .await?
            .hash(password)
            .or_internal()?;
        self.ports
            .user_store
            .save(tenant, user)
            .await
            .or_internal()?;
        self.ports
            .credential_store
            .update_password_hash(tenant, user.id(), &hash)
            .await
            .or_internal()?;
        let stores = RoleStores {
            role_store: self.ports.role_store.as_ref(),
            assignment_store: self.ports.assignment_store.as_ref(),
        };
        starting_roles::grant(stores, tenant, *user.id(), Vec::new()).await
    }
}

impl Command for SignUpUseCase {
    type Caller = ScopedTenant;
    type Input = SignUpRequest;
    type Output = Result<SignUpOutcome, AppError>;

    /// Opens an unconfirmed account in `tenant`, if it takes sign-ups, and
    /// mails a link to confirm the address. Both outcomes are answered the
    /// same way to whoever filled in the form.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` if the tenant does not take sign-ups, is not
    ///   open, signs nobody in with a password, or is at its user limit, or
    ///   the deployment has no mail server, so the new account could never
    ///   confirm its address. That refusal comes before any address is
    ///   looked up, alike for every address.
    /// - `AppError::Domain` if the password breaks the tenant's rules.
    /// - `AppError::NotFound` if the tenant no longer exists.
    /// - `AppError::Busy` if no password hash could start on this node in
    ///   time, for a new address and a taken one alike.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: SignUpRequest,
    ) -> Result<SignUpOutcome, AppError> {
        let SignUpRequest {
            person,
            limits,
            scope,
        } = request;
        let admitted = self.admitted(tenant, &person.password).await?;
        self.ports.verification_links.ensure_mailable(NO_SIGN_UPS)?;
        let limit_enforcer = self.ports.limit_enforcer.as_ref();
        ensure_room(limit_enforcer, tenant, &limits, ResourceKind::Users).await?;
        let registered =
            User::register(UserId::new(), person.email, person.display_name, &admitted);
        let mut user = registered.map_err(AppError::from_domain)?;
        let chosen = Secret::new(person.password);
        self.vet(tenant, &user, &chosen).await?;
        if is_registered(self.ports.user_store.as_ref(), tenant, user.email()).await? {
            return self.already_registered(chosen.expose()).await;
        }

        self.store(tenant, &user, chosen.expose()).await?;
        self.ports
            .verification_links
            .send(tenant, &user, &scope)
            .await?;
        let actor = ActorRef::User(*user.id());
        auditor
            .dispatch_by(&actor, user.take_events(tenant))
            .await
            .or_internal()?;
        Ok(SignUpOutcome::Created(*user.id()))
    }
}

/// Whether the address already has an account in `tenant`.
async fn is_registered(
    users: &dyn UserStore,
    tenant: &ScopedTenant,
    email: &Email,
) -> Result<bool, AppError> {
    users.email_exists(tenant, email).await.or_internal()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::tenant::access::auth_config::{
        SelfRegistration, TenantAuthSettings,
    };

    use super::*;
    use crate::test_support::authentication::{BusyHashPermits, CountingHasher, hashing_with};
    use crate::test_support::identity::{
        FakeTokenStore, FakeUserStore, RecordingCredentialStore, verification_links_over,
        verification_links_reaching,
    };
    use crate::test_support::tenant::{FakeTenantStore, cfg, tenant_store_signing_in_with};
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, RejectingLimitEnforcer, block_on,
        test_auditor, test_ctx, test_link_scope,
    };

    const PASSWORD: &str = "Signing1Up2Today";

    fn settings(registration: SelfRegistration, methods: Vec<AuthMethod>) -> Arc<FakeTenantStore> {
        tenant_store_signing_in_with(TenantAuthSettings {
            self_registration: registration,
            enabled_methods: methods,
            ..TenantAuthSettings::default()
        })
    }

    fn open_tenant() -> Arc<FakeTenantStore> {
        settings(SelfRegistration::Open, vec![AuthMethod::Password])
    }

    /// The stores that watch a sign-up.
    #[derive(Default)]
    struct Harness {
        users: Arc<FakeUserStore>,
        credentials: Arc<RecordingCredentialStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Harness {
        fn ports(&self, tenants: Arc<FakeTenantStore>) -> SignUpPorts {
            SignUpPorts {
                tenant_store: tenants,
                user_store: self.users.clone(),
                credential_store: self.credentials.clone(),
                verification_links: verification_links_over(
                    &Arc::new(FakeTokenStore::empty()),
                    &self.mailer,
                ),
                ..SignUpPorts::fakes()
            }
        }

        fn sign_up(
            &self,
            ports: SignUpPorts,
            email: &str,
            password: &str,
        ) -> Result<SignUpOutcome, AppError> {
            block_on(SignUpUseCase::new(ports).execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                SignUpRequest {
                    person: SignUp {
                        email: Email::new(email).unwrap(),
                        display_name: DisplayName::new("New Person", &cfg().display_name).unwrap(),
                        password: password.to_owned(),
                    },
                    limits: test_ctx().plan_limits().clone(),
                    scope: test_link_scope(),
                },
            ))
        }
    }

    fn created(outcome: &Result<SignUpOutcome, AppError>) -> Option<UserId> {
        match outcome {
            Ok(SignUpOutcome::Created(user_id)) => Some(*user_id),
            Ok(SignUpOutcome::AlreadyRegistered) | Err(_) => None,
        }
    }

    /// Ann signs up to a tenant that takes sign-ups. Her account waits for
    /// her to confirm the link mailed to her, her password is kept, and the
    /// sign-up is recorded.
    #[test]
    fn an_open_tenant_creates_an_unconfirmed_account() {
        let h = Harness::default();

        let outcome = h.sign_up(h.ports(open_tenant()), "new@acme.com", PASSWORD);

        let user_id = created(&outcome).unwrap();
        assert_eq!(
            h.users.get_status(&user_id),
            Some(UserStatus::PendingVerification)
        );
        assert!(h.credentials.hash_of(&user_id).is_some());
        assert_eq!(h.mailer.recipients(), ["new@acme.com"]);
        assert_eq!(
            h.sink.records.lock().unwrap().as_slice(),
            ["identity.user_registered"]
        );
    }

    /// Sign-up to an open tenant is refused without mail setup. The
    /// response points to an administrator, and no account or outgoing
    /// mail is created.
    #[test]
    fn signing_up_is_refused_where_nothing_is_mailed() {
        let h = Harness::default();
        let ports = SignUpPorts {
            verification_links: verification_links_reaching(
                &Arc::new(FakeTokenStore::empty()),
                &h.mailer,
                FakeMailSetup::not_set_up(),
            ),
            ..h.ports(open_tenant())
        };

        let result = h.sign_up(ports, "new@acme.com", PASSWORD);

        assert!(
            matches!(result, Err(AppError::Forbidden(why)) if why.as_str().contains("administrator"))
        );
        assert_eq!(h.users.count(), 0);
        assert_eq!(h.mailer.count(), 0);
    }

    /// A tenant with self-registration closed refuses sign-up and creates
    /// no account.
    #[test]
    fn a_tenant_that_has_not_turned_sign_up_on_refuses_it() {
        let h = Harness::default();
        let tenants = settings(SelfRegistration::Closed, vec![AuthMethod::Password]);

        let result = h.sign_up(h.ports(tenants), "new@acme.com", PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(h.users.count(), 0);
    }

    /// A tenant that signs people in only with passkeys takes no sign-up
    /// with a password.
    #[test]
    fn a_tenant_without_password_sign_in_takes_no_sign_ups() {
        let h = Harness::default();
        let tenants = settings(SelfRegistration::Open, vec![AuthMethod::Passkey]);

        let result = h.sign_up(h.ports(tenants), "new@acme.com", PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Bob signs up with an address that already has an account. He gets the
    /// same answer, and nothing is made, mailed or recorded.
    #[test]
    fn an_address_that_already_has_an_account_creates_nothing() {
        let h = Harness::default();
        h.users.add_active_user(UserId::new(), "taken@acme.com");

        let outcome = h.sign_up(h.ports(open_tenant()), "taken@acme.com", PASSWORD);

        assert!(matches!(outcome, Ok(SignUpOutcome::AlreadyRegistered)));
        assert_eq!(h.users.count(), 1);
        assert_eq!(h.mailer.count(), 0);
        assert!(h.sink.records.lock().unwrap().is_empty());
    }

    /// How many passwords a sign-up with `email` hashes, in a tenant where
    /// `taken@acme.com` already has an account.
    fn hashes_for(email: &str) -> usize {
        let h = Harness::default();
        h.users.add_active_user(UserId::new(), "taken@acme.com");
        let hasher = Arc::new(CountingHasher::default());
        let ports = SignUpPorts {
            hashing: hashing_with(hasher.clone()),
            ..h.ports(open_tenant())
        };
        h.sign_up(ports, email, PASSWORD).unwrap();
        hasher.hashed()
    }

    /// Sign-up hashes the password the same number of times for an address
    /// already registered and for a new address.
    #[test]
    fn a_taken_address_costs_as_much_hashing_as_a_new_one() {
        let new = hashes_for("new@acme.com");

        let taken = hashes_for("taken@acme.com");

        assert_eq!(taken, new);
    }

    /// When a hash permit is unavailable, sign-up reports that the node is
    /// busy. No hash runs and no account is created.
    #[test]
    fn a_busy_node_signs_nobody_up() {
        let h = Harness::default();
        let hasher = Arc::new(CountingHasher::default());
        let ports = SignUpPorts {
            hashing: PasswordHashing::new(hasher.clone(), Arc::new(BusyHashPermits)),
            ..h.ports(open_tenant())
        };

        let result = h.sign_up(ports, "new@acme.com", PASSWORD);

        assert!(matches!(result, Err(AppError::Busy)));
        assert_eq!(hasher.hashed(), 0);
        assert_eq!(h.users.count(), 0);
    }

    /// Ann's password is too short for the tenant. It is refused and no
    /// account is made.
    #[test]
    fn a_password_that_breaks_the_tenants_rules_is_refused() {
        let h = Harness::default();

        let result = h.sign_up(h.ports(open_tenant()), "new@acme.com", "short");

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(h.users.count(), 0);
    }

    /// The tenant is at its plan's user limit. Ann's sign-up is refused and
    /// no account is made.
    #[test]
    fn sign_up_is_refused_at_the_user_limit() {
        let h = Harness::default();
        let ports = SignUpPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..h.ports(open_tenant())
        };

        let result = h.sign_up(ports, "new@acme.com", PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(h.users.count(), 0);
    }
}
