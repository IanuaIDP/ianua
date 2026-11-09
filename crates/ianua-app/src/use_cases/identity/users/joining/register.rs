//! Register user: an admin adds an account to the tenant, with a password
//! and the roles they hand out, and a link goes to its address to confirm
//! it.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::breach::NewPasswordBreach;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DisplayName, Email, PasswordHash, PrincipalRef, RoleId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::email::{EmailVerification, LinkScope};
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CredentialStore;
use crate::ports::authorization::{AccessRecordStore, RoleAssignmentStore, RoleStore};
use crate::ports::identity::UserStore;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::tenant::TenantStore;
use crate::ports::workflows::ChangeGuard;
use crate::services::authentication::channels::NO_PENDING_ACCOUNTS;
use crate::services::authentication::new_password::{NewPassword, NewPasswordPorts};
use crate::services::authorization::starting_roles::{self, RoleStores};
use crate::services::guarded::{AdminHolder, ensure_admin_rules_allow};
use crate::services::identity::address_free::ensure_email_free;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::email::VerificationLinks;
use crate::use_cases::identity::users::credentials::new_password::{MadePassword, PasswordMaker};
use crate::use_cases::identity::users::joining::room::ensure_room;
use crate::use_cases::identity::users::records::role_grants::{self, Grants, NamedRoles};

/// The user a caller is asking to have created.
pub struct New {
    /// The address the account signs in with.
    pub email: Email,
    /// The name shown to other people in the tenant.
    pub display_name: DisplayName,
    /// `None` generates one, returned exactly once in the result.
    pub password: Option<String>,
    /// Whether the account may sign in at once, or waits for its holder to
    /// confirm the address. Either way the address stays unconfirmed until
    /// they follow the link mailed to it.
    pub verification: EmailVerification,
    /// Roles to grant on top of the tenant's defaults. A role that is both is
    /// granted once, so naming a default is agreement rather than a conflict.
    pub roles: Vec<RoleId>,
    /// Where the confirmation link lands.
    pub scope: LinkScope,
}

/// What registering a user made.
pub struct RegisterResult {
    /// The new user's id.
    pub id: UserId,
    /// The generated password, only when none was given.
    pub generated_password: Option<Secret>,
    /// What the breach check found of the password, so an admin whose
    /// tenant only warns is told.
    pub breach: NewPasswordBreach,
}

/// The ports [`RegisterUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RegisterPorts {
    /// Saves users and finds addresses already taken.
    pub user_store: Arc<dyn UserStore>,
    /// Holds the tenant to its plan's user limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Writes the new user's password hash.
    pub credential_store: Arc<dyn CredentialStore>,
    /// Reads the tenant's password rules.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Reads the roles named and the tenant's defaults.
    pub role_store: Arc<dyn RoleStore>,
    /// Records the roles the new user starts with.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Mails the link that confirms the new address.
    pub verification_links: Arc<VerificationLinks>,
    /// Checks or draws the new user's password, and hashes it.
    pub passwords: Arc<PasswordMaker>,
    /// Checks the password against breaches and the common list.
    pub new_password: NewPasswordPorts,
    /// The company's "before" rules, asked before an admin role is named.
    pub guard: Arc<dyn ChangeGuard>,
}

/// Registers a user in the caller's tenant.
pub struct RegisterUseCase {
    ports: RegisterPorts,
}

impl RegisterUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RegisterPorts) -> Self {
        Self { ports }
    }

    /// The supplied password once it meets the tenant's policy, or a drawn
    /// one, checked for `user`'s name and address, the common list and
    /// known breaches, with what the breach check found.
    async fn password(
        &self,
        ctx: &CallerContext,
        user: &User<ResolvedTenant>,
        supplied: Option<String>,
    ) -> Result<(MadePassword, NewPasswordBreach), AppError> {
        let tenant = ctx.tenant();
        let workspace = existing_tenant(self.ports.tenant_store.as_ref(), &tenant).await?;
        let policy = workspace.auth_config().password_policy();
        let made = self.ports.passwords.made(policy, supplied).await?;
        let new = NewPassword {
            tenant: &tenant,
            account: user,
            chosen: &made.secret,
        };
        let breach = self.ports.new_password.screened(&workspace, new).await?;
        Ok((made, breach))
    }

    /// The roles named for `user` and their assignments, once the caller
    /// may hand each of them out.
    async fn named_roles(
        &self,
        tenant: &ScopedTenant,
        authority: &TenantAuthority,
        user: &User<ResolvedTenant>,
        roles: &[RoleId],
    ) -> Result<Grants, AppError> {
        let named = NamedRoles {
            principal: PrincipalRef::User(*user.id()),
            roles,
            granter: authority,
        };
        role_grants::grants(self.ports.role_store.as_ref(), tenant, named).await
    }

    /// Asks the company's "before admin given" rules about each admin role
    /// `grants` gives `user`.
    async fn ensure_rules_allow(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        user: &User<ResolvedTenant>,
        grants: &Grants,
    ) -> Result<(), AppError> {
        let holder = PrincipalRef::User(*user.id());
        let guard = self.ports.guard.as_ref();
        for role in &grants.roles {
            let reach = AdminHolder::Principal(&holder);
            ensure_admin_rules_allow(guard, tenant, auditor, role, reach).await?;
        }
        Ok(())
    }

    /// Refuses an account that would wait for a mailed link to join, on a
    /// deployment with no mail server. One let in at once needs no link.
    fn ensure_may_join(&self, verification: EmailVerification) -> Result<(), AppError> {
        if verification.is_automatic() {
            return Ok(());
        }
        self.ports
            .verification_links
            .ensure_mailable(NO_PENDING_ACCOUNTS)
    }

    /// Refuses an account that could not join: one waiting for a mailed
    /// link where nothing is mailed, or one past the plan's user limit.
    async fn ensure_room_to_join(
        &self,
        ctx: &CallerContext,
        verification: EmailVerification,
    ) -> Result<(), AppError> {
        self.ensure_may_join(verification)?;
        let limits = self.ports.limit_enforcer.as_ref();
        ensure_room(
            limits,
            &ctx.tenant(),
            ctx.plan_limits(),
            ResourceKind::Users,
        )
        .await
    }

    /// Lets the new account in at once when the caller asked for that and
    /// may let accounts in.
    async fn admit(
        &self,
        ctx: &CallerContext,
        authority: &TenantAuthority,
        user: &mut User<ResolvedTenant>,
        verification: EmailVerification,
    ) -> Result<(), AppError> {
        if !verification.is_automatic() {
            return Ok(());
        }
        let control = account_control(
            self.ports.access_records.as_ref(),
            &ctx.tenant(),
            authority,
            user.id(),
            AccountAction::LetIn,
        )
        .await?;
        user.activate(&control).map_err(AppError::from_domain)?;
        Ok(())
    }

    /// Mails the saved `user` a link to confirm their address, and records
    /// what their account raised, the link going out among it.
    async fn mail_and_record(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        user: &mut User<ResolvedTenant>,
        scope: &LinkScope,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let links = &self.ports.verification_links;
        links.send(&tenant, user, scope).await?.note_on(user);
        auditor
            .dispatch_by(&ctx.actor(), user.take_events(&tenant))
            .await
            .or_internal()
    }

    /// Saves the new user, the hash of their password and the roles they
    /// start with.
    async fn store(
        &self,
        ctx: &CallerContext,
        user: &User<ResolvedTenant>,
        password_hash: &PasswordHash,
        named: Vec<RoleAssignment<ResolvedTenant>>,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        self.ports
            .user_store
            .save(&tenant, user)
            .await
            .or_internal()?;
        self.ports
            .credential_store
            .update_password_hash(&tenant, user.id(), password_hash)
            .await
            .or_internal()?;
        let stores = RoleStores {
            role_store: self.ports.role_store.as_ref(),
            assignment_store: self.ports.assignment_store.as_ref(),
        };
        starting_roles::grant(stores, &tenant, *user.id(), named).await
    }
}

impl Command for RegisterUseCase {
    type Caller = CallerContext;
    type Input = New;
    type Output = Result<RegisterResult, AppError>;

    /// Registers a new user, generating a password when none is given, and
    /// mails a link to confirm their address.
    ///
    /// With [`EmailVerification::Required`] the account waits in
    /// `PendingVerification` until its holder follows the link. With
    /// [`EmailVerification::Automatic`] it is let in at once, which needs the
    /// right to let accounts in. Nobody vouches for an address: it stays
    /// unconfirmed until the link is followed. Automatic admission also works
    /// without mail, leaving the address unconfirmed and sending no link.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for a full plan, missing creation/grant/activation rights, or a mailed-link wait without mail.
    /// - `AppError::Conflict` for a taken address; `NotFound` for a missing role.
    /// - `AppError::Domain` for a supplied password outside policy; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        new_user: New,
    ) -> Result<RegisterResult, AppError> {
        let New {
            email,
            display_name,
            password,
            verification,
            roles,
            scope,
        } = new_user;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ensure_room_to_join(ctx, verification).await?;
        let registered = User::register(UserId::new(), email, display_name, &authority.standing());
        let mut user = registered.map_err(AppError::from_domain)?;
        let named = self.named_roles(&tenant, &authority, &user, &roles).await?;
        ensure_email_free(self.ports.user_store.as_ref(), &tenant, user.email()).await?;
        self.admit(ctx, &authority, &mut user, verification).await?;
        let (made, breach) = self.password(ctx, &user, password).await?;
        self.ensure_rules_allow(&tenant, auditor, &user, &named)
            .await?;

        self.store(ctx, &user, &made.hash, named.assignments)
            .await?;
        self.mail_and_record(ctx, auditor, &mut user, &scope)
            .await?;
        Ok(RegisterResult {
            id: *user.id(),
            generated_password: made.generated(),
            breach,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{CharacterRequirements, Label, PasswordPolicy};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeRoleAssignmentStore, FakeRoleStore};
    use crate::test_support::identity::{
        FakeTokenStore, FakeUserStore, verification_links_over, verification_links_reaching,
    };
    use crate::test_support::tenant::{
        FakeTenantStore, cfg, tenant_store_with_password_policy, test_tenant_for_ctx,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, FakeMailer, RejectingLimitEnforcer, block_on,
        test_auditor, test_ctx, test_link_scope,
    };

    fn role(
        name: &str,
        system: Vec<SystemPermission>,
        assignment: DefaultAssignment,
    ) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", name).unwrap(),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment,
        })
    }

    /// A tenant whose new users get `Member`, with a `Support` role that may
    /// manage users, and the stores that watch a registration.
    struct Tenant {
        member: RoleId,
        support: RoleId,
        users: Arc<FakeUserStore>,
        roles: Arc<FakeRoleStore>,
        assignments: Arc<FakeRoleAssignmentStore>,
        tokens: Arc<FakeTokenStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tenant {
        fn new() -> Self {
            let member = role("Member", Vec::new(), DefaultAssignment::NewUsers);
            let support = role(
                "Support",
                vec![SystemPermission::Users(UserAction::Manage)],
                DefaultAssignment::Manual,
            );
            Self {
                member: *member.id(),
                support: *support.id(),
                users: Arc::new(FakeUserStore::empty()),
                roles: Arc::new(FakeRoleStore::holding(
                    test_ctx().tenant_id(),
                    [member, support],
                )),
                assignments: Arc::new(FakeRoleAssignmentStore::empty()),
                tokens: Arc::new(FakeTokenStore::empty()),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> RegisterPorts {
            RegisterPorts {
                user_store: self.users.clone(),
                tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                role_store: self.roles.clone(),
                assignment_store: self.assignments.clone(),
                verification_links: verification_links_over(&self.tokens, &self.mailer),
                ..RegisterPorts::fakes()
            }
        }

        fn register(
            &self,
            ports: RegisterPorts,
            new_user: New,
        ) -> Result<RegisterResult, AppError> {
            let use_case = RegisterUseCase::new(ports);
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), new_user))
        }

        fn holds(&self, user_id: UserId, role_id: RoleId) -> bool {
            block_on(self.assignments.exists(
                &test_ctx().tenant(),
                &PrincipalRef::User(user_id),
                &role_id,
            ))
            .unwrap()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn alice() -> New {
        New {
            email: Email::new("alice@acme.com").unwrap(),
            display_name: DisplayName::new("Alice Smith", &cfg().display_name).unwrap(),
            password: None,
            verification: EmailVerification::Required,
            roles: Vec::new(),
            scope: test_link_scope(),
        }
    }

    fn alice_with(roles: Vec<RoleId>) -> New {
        New { roles, ..alice() }
    }

    /// Ann registers Alice. Her account waits for her to confirm the address,
    /// a link goes to it, and the registration is recorded.
    #[test]
    fn a_registered_user_waits_for_the_link_mailed_to_them() {
        let tenant = Tenant::new();

        let result = tenant.register(tenant.ports(), alice()).unwrap();

        assert_eq!(
            tenant.users.get_status(&result.id),
            Some(UserStatus::PendingVerification)
        );
        assert_eq!(tenant.tokens.count(), 1);
        assert_eq!(tenant.mailer.recipients(), ["alice@acme.com"]);
        assert_eq!(tenant.records()[0], "identity.user_registered");
        assert!(result.generated_password.is_some());
    }

    /// Ann registers Alice to sign in at once. Alice is active, but her
    /// address stays unconfirmed and the link still goes out: Ann's word
    /// does not prove the mailbox is Alice's.
    #[test]
    fn an_account_let_in_at_once_still_confirms_its_address() {
        let tenant = Tenant::new();
        let new_user = New {
            verification: EmailVerification::Automatic,
            ..alice()
        };

        let result = tenant.register(tenant.ports(), new_user).unwrap();

        let stored = block_on(tenant.users.find_by_id(&test_ctx().tenant(), &result.id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.status(), UserStatus::Active);
        assert!(!stored.email_verified());
        assert_eq!(tenant.mailer.count(), 1);
    }

    /// The tenant's ports, on a deployment with no mail server.
    fn without_mail(tenant: &Tenant) -> RegisterPorts {
        RegisterPorts {
            verification_links: verification_links_reaching(
                &tenant.tokens,
                &tenant.mailer,
                FakeMailSetup::not_set_up(),
            ),
            ..tenant.ports()
        }
    }

    /// Registration requiring email verification is refused without mail
    /// setup. No account is created, no mail is sent and no event is recorded.
    #[test]
    fn an_account_waiting_for_a_mail_is_refused_where_nothing_is_mailed() {
        let tenant = Tenant::new();

        let result = tenant.register(without_mail(&tenant), alice());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
        assert_eq!(tenant.mailer.count(), 0);
        assert!(tenant.records().is_empty());
    }

    /// Ann registers Alice to sign in at once on a deployment with no mail
    /// server. Alice is let in, her address left unconfirmed, and no link
    /// is made or mailed.
    #[test]
    fn an_account_let_in_at_once_is_made_where_nothing_is_mailed() {
        let tenant = Tenant::new();
        let new_user = New {
            verification: EmailVerification::Automatic,
            ..alice()
        };

        let result = tenant.register(without_mail(&tenant), new_user).unwrap();

        let stored = block_on(tenant.users.find_by_id(&test_ctx().tenant(), &result.id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.status(), UserStatus::Active);
        assert_eq!(tenant.tokens.count(), 0);
        assert_eq!(tenant.mailer.count(), 0);
    }

    /// Ann names Member, which every new user gets anyway. Alice holds it
    /// once and nothing fails.
    #[test]
    fn requesting_the_default_role_is_not_a_conflict() {
        let tenant = Tenant::new();

        let result = tenant
            .register(tenant.ports(), alice_with(vec![tenant.member]))
            .unwrap();

        assert!(tenant.holds(result.id, tenant.member));
        assert_eq!(tenant.assignments.count(), 1);
    }

    /// Ann names Support. Alice holds it besides Member.
    #[test]
    fn a_requested_role_is_granted_alongside_the_defaults() {
        let tenant = Tenant::new();

        let result = tenant
            .register(tenant.ports(), alice_with(vec![tenant.support]))
            .unwrap();

        assert!(tenant.holds(result.id, tenant.member));
        assert!(tenant.holds(result.id, tenant.support));
        assert_eq!(tenant.assignments.count(), 2);
    }

    /// Ann's picker names Support twice. It is given once.
    #[test]
    fn a_role_named_twice_is_granted_once() {
        let tenant = Tenant::new();

        tenant
            .register(
                tenant.ports(),
                alice_with(vec![tenant.support, tenant.support, tenant.member]),
            )
            .unwrap();

        assert_eq!(tenant.assignments.count(), 2);
    }

    /// A caller with only user-creation rights cannot register Alice with
    /// the Support role's user-management rights. The refusal creates no
    /// account or role assignment.
    #[test]
    fn a_role_the_caller_cannot_hand_out_is_refused_before_the_user_exists() {
        let tenant = Tenant::new();
        let ports = RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Create),
            ])),
            ..tenant.ports()
        };

        let result = tenant.register(ports, alice_with(vec![tenant.support]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
        assert_eq!(tenant.assignments.count(), 0);
    }

    /// Ann names a role the tenant does not have. It is not found and Alice
    /// is not made.
    #[test]
    fn a_role_that_does_not_exist_is_not_found() {
        let tenant = Tenant::new();

        let result = tenant.register(tenant.ports(), alice_with(vec![RoleId::new()]));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// Sam may create users and nothing more. The default role still
    /// reaches Alice: the tenant gives it, not Sam.
    #[test]
    fn the_defaults_need_no_permission_to_be_granted() {
        let tenant = Tenant::new();
        let ports = RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Create),
            ])),
            ..tenant.ports()
        };

        tenant.register(ports, alice()).unwrap();

        assert_eq!(tenant.assignments.count(), 1);
    }

    /// Ann registers Alice twice. The second is a conflict, nothing more is
    /// stored and nothing more recorded.
    #[test]
    fn a_taken_address_is_a_conflict() {
        let tenant = Tenant::new();
        tenant.register(tenant.ports(), alice()).unwrap();
        let recorded = tenant.records().len();

        let result = tenant.register(tenant.ports(), alice());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.users.count(), 1);
        assert_eq!(tenant.records().len(), recorded);
    }

    /// The tenant is at its plan's user limit. Ann's registration is
    /// refused and nobody is made.
    #[test]
    fn registration_is_refused_at_the_user_limit() {
        let tenant = Tenant::new();
        let ports = RegisterPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..tenant.ports()
        };

        let result = tenant.register(ports, alice());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// The tenant asks for 20 characters, and Ann gives Alice 15. It is
    /// refused and Alice is not made.
    #[test]
    fn a_supplied_password_is_held_to_the_tenants_policy() {
        let tenant = Tenant::new();
        let ports = RegisterPorts {
            tenant_store: tenant_store_with_password_policy(
                PasswordPolicy::new(20, CharacterRequirements::strict()).unwrap(),
            ),
            ..tenant.ports()
        };
        let new_user = New {
            password: Some("Fifteen1Chars!!".to_owned()),
            ..alice()
        };

        let result = tenant.register(ports, new_user);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// User-viewing rights do not permit registering Alice. The request is
    /// refused and no account is created.
    #[test]
    fn a_caller_who_may_not_create_users_is_refused() {
        let tenant = Tenant::new();
        let ports = RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..tenant.ports()
        };

        let result = tenant.register(ports, alice());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// A caller with only user-creation rights cannot register Alice for
    /// immediate sign-in. The request is refused and no account is created.
    #[test]
    fn letting_an_account_in_at_once_needs_the_right_to() {
        let tenant = Tenant::new();
        let ports = RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Create),
            ])),
            ..tenant.ports()
        };
        let new_user = New {
            verification: EmailVerification::Automatic,
            ..alice()
        };

        let result = tenant.register(ports, new_user);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
    }

    /// A signed-out caller cannot register Alice and is refused as
    /// unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::new();
        let ports = RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.register(ports, alice());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ann's company rule refuses every role holding a built-in permission.
    /// Tess registers Alice with Support: it is refused before Alice's
    /// account is made.
    #[test]
    fn a_company_rule_refusing_stops_a_registration_naming_an_admin_role() {
        let tenant = Tenant::new();
        let ports = RegisterPorts {
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..tenant.ports()
        };

        let result = tenant.register(ports, alice_with(vec![tenant.support]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 0);
        assert_eq!(tenant.assignments.count(), 0);
    }

    /// The same rule is not asked about Member, which does no admin work:
    /// Alice is registered with it.
    #[test]
    fn a_registration_naming_no_admin_role_is_not_asked_about() {
        let tenant = Tenant::new();
        let ports = RegisterPorts {
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..tenant.ports()
        };

        let result = tenant.register(ports, alice_with(vec![tenant.member]));

        assert!(tenant.holds(result.unwrap().id, tenant.member));
    }
}
