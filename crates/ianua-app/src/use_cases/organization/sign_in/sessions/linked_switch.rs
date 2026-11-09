//! A tenant user switching to their linked account in another tenant of
//! the organization, without signing in again.
//!
//! Everything about who switches comes from the caller's own session,
//! never from the request. The caller's account names the linked identity
//! by its address, and the domain checks that the identity leads back to
//! that very account, that both accounts still hold the group's verified
//! address, and that the target tenant admits the sign-in carried over. A
//! sign-in that proved no second factor owes what a sign-in to the target
//! account would.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::mfa::owed::{
    CodeFactorHolding, HeldFactors, SecondFactor,
};
use ianua_domain::domains::authentication::sessions::session::{CreateSessionParams, Session};
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::organization::events::access::TenantSwitched;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::linked_identity::{
    LinkedIdentity, LinkedMemberAccount, TenantSwitch,
};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, SessionId, TenantId, UserId};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{MfaEnrollmentStore, PasskeyStore};
use crate::ports::identity::UserStore;
use crate::ports::organization::{LinkedIdentityLookup, OrganizationStore};
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::{existing_tenant, existing_user};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_organization;

/// A switch that opened a session on the linked account. It holds the
/// refresh token, so it has no `Debug`.
pub struct LinkedSwitchSuccess {
    /// The new session, in the target tenant.
    pub session_id: SessionId,
    /// The raw refresh token, sent to the client and never stored.
    pub refresh_token: Secret,
    /// The tenant switched to.
    pub tenant_id: TenantId,
    /// The linked account signed in to there.
    pub user_id: UserId,
    /// What the new session still owes in the way of a second factor.
    pub second_factor: SecondFactor,
}

/// The ports [`LinkedTenantSwitchUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct LinkedTenantSwitchPorts {
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The organization both tenants belong to.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Both tenants, which name the audit record and set the target's
    /// rules.
    pub tenants: Arc<dyn TenantStore>,
    /// The linked account in the target tenant.
    pub users: Arc<dyn UserStore>,
    /// The caller's linked identity, found by their address.
    pub identities: Arc<dyn LinkedIdentityLookup>,
    /// The linked account's authenticator app.
    pub enrollments: Arc<dyn MfaEnrollmentStore>,
    /// The linked account's passkeys.
    pub passkeys: Arc<dyn PasskeyStore>,
    /// Where the new session is kept.
    pub sessions: Arc<dyn SessionStore>,
    /// Makes the new session's refresh token.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Switches the caller to their linked account in another tenant.
pub struct LinkedTenantSwitchUseCase {
    ports: LinkedTenantSwitchPorts,
}

/// Both ends of a switch, loaded fresh.
struct Ends {
    organization: Organization,
    source: Tenant,
    target: Tenant,
    target_user: User<ResolvedTenant>,
}

impl LinkedTenantSwitchUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: LinkedTenantSwitchPorts) -> Self {
        Self { ports }
    }

    /// The caller's linked identity, found by their own account's address.
    async fn callers_identity(
        &self,
        ctx: &CallerContext,
        person: &SignedInAccount,
    ) -> Result<LinkedIdentity, AppError> {
        self.ports
            .identities
            .find_by_email(&ctx.organization_id(), person.account.email())
            .await
            .or_internal()?
            .or_not_found(message!(
                "organization-no-linked-identity",
                "no linked identity"
            ))
    }

    /// The organization, both tenants and the linked account in `target`.
    async fn ends(
        &self,
        ctx: &CallerContext,
        linked: &LinkedIdentity,
        target: TenantId,
    ) -> Result<Ends, AppError> {
        let target_user_id = linked_account_in(linked, &target)?;
        let organization =
            existing_organization(self.ports.organizations.as_ref(), &ctx.organization_id())
                .await?;
        let tenants = self.ports.tenants.as_ref();
        let source = existing_tenant(tenants, &ctx.tenant_id()).await?;
        let target_tenant = existing_tenant(tenants, &target).await?;
        let scope = ScopedTenant::from_registry(&target_tenant);
        let target_user = existing_user(self.ports.users.as_ref(), &scope, &target_user_id).await?;
        Ok(Ends {
            organization,
            source,
            target: target_tenant,
            target_user,
        })
    }

    /// What a sign-in to `user` in `tenant` owes when only their own
    /// factors ask: theirs if they hold one, one to set up if the tenant
    /// requires it.
    async fn linked_account_owes(
        &self,
        tenant: &Tenant,
        user: &User<ResolvedTenant>,
    ) -> Result<SecondFactor, AppError> {
        let scope = ScopedTenant::from_registry(tenant);
        let app = self
            .ports
            .enrollments
            .find_by_user(&scope, user.id())
            .await
            .or_internal()?;
        let totp = app
            .filter(MfaEnrollment::is_active)
            .map_or(CodeFactorHolding::None, |_| CodeFactorHolding::Active);
        let keys = self.ports.passkeys.list_by_user(&scope, user.id()).await;
        let held = HeldFactors::new(totp, keys.or_internal()?.len());
        Ok(SecondFactor::for_enrolment(
            tenant.auth_config().mfa_policy(),
            held.enrolment(),
        ))
    }

    /// The session the switch opens on the linked account, with its raw
    /// refresh token.
    fn opened(
        &self,
        person: &SignedInAccount,
        linked: &LinkedIdentity,
        ends: &Ends,
        target_owes: SecondFactor,
    ) -> Result<(Session<ResolvedTenant>, Secret), AppError> {
        let account = linked
            .switch_target(&switch_of(person, ends, target_owes))
            .map_err(AppError::from_domain)?;
        let (raw, hash) = self
            .ports
            .token_generator
            .generate()
            .or_internal()?
            .into_parts();
        let params = CreateSessionParams {
            id: SessionId::new(),
            refresh_token_hash: hash,
            ip_address: person.session.ip_address().cloned(),
            user_agent: person.session.user_agent().cloned(),
            timeout: ends
                .target
                .auth_config()
                .session_timeout()
                .map_err(AppError::from_domain)?,
        };
        Ok((Session::create(account, params), raw))
    }
}

impl Command for LinkedTenantSwitchUseCase {
    type Caller = CallerContext;
    type Input = TenantId;
    type Output = Result<LinkedSwitchSuccess, AppError>;

    /// Opens a session on the caller's linked account in `target` and
    /// records `organization.tenant_switched`. The session is kept in the
    /// target tenant, under the linked account.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::NotFound` when the caller has no linked identity, or the
    ///   organization, a tenant or the linked account is gone.
    /// - `AppError::Forbidden` when the identity has no account in `target`,
    ///   or the domain refuses the switch: the identity is not the
    ///   caller's, an account lost the group's verified address or may not
    ///   sign in, the target does not admit the sign-in, or the sign-in has
    ///   not finished.
    /// - `AppError::Domain` when the target's session settings are out of
    ///   range.
    /// - `AppError::Internal` on storage, token or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        target: TenantId,
    ) -> Result<LinkedSwitchSuccess, AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let linked = self.callers_identity(ctx, &person).await?;
        let ends = self.ends(ctx, &linked, target).await?;
        let owes = self
            .linked_account_owes(&ends.target, &ends.target_user)
            .await?;
        let (session, refresh_token) = self.opened(&person, &linked, &ends, owes)?;
        let scope = ScopedTenant::from_registry(&ends.target);
        self.ports
            .sessions
            .save(&scope, &session)
            .await
            .or_internal()?;
        let switch = switch_of(&person, &ends, owes);
        let switched = TenantSwitched::recorded(&switch, &ends.source, &session);
        auditor
            .dispatch_by(&ActorRef::User(*person.account.id()), vec![switched])
            .await
            .or_internal()?;
        Ok(LinkedSwitchSuccess {
            session_id: *session.id(),
            refresh_token,
            tenant_id: target,
            user_id: *ends.target_user.id(),
            second_factor: session.owed(),
        })
    }
}

/// The account `linked` holds in `target`.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when the identity has no account there.
fn linked_account_in(linked: &LinkedIdentity, target: &TenantId) -> Result<UserId, AppError> {
    linked
        .links()
        .iter()
        .find(|link| link.tenant_id() == target)
        .map(|link| *link.user_id())
        .ok_or_else(|| {
            AppError::Forbidden(message!(
                "organization-not-linked-to-the-target-tenant",
                "not linked to the target tenant"
            ))
        })
}

/// The switch from the caller's session to the linked account `ends`
/// holds, owing `target_owes` when the carried sign-in proved no factor.
fn switch_of<'a>(
    person: &'a SignedInAccount,
    ends: &'a Ends,
    target_owes: SecondFactor,
) -> TenantSwitch<'a, ResolvedTenant, ResolvedTenant> {
    TenantSwitch {
        organization: &ends.organization,
        from: LinkedMemberAccount {
            tenant_id: *ends.source.id(),
            user: &person.account,
        },
        to: LinkedMemberAccount {
            tenant_id: *ends.target.id(),
            user: &ends.target_user,
        },
        target_tenant: &ends.target,
        target_policy: ends.target.auth_config().step_up_policy(),
        signed_in: &person.signed_in,
        target_owes,
        client_ip: person.session.ip_address(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::MfaPolicy;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::organization::members::linked_identity::{
        LinkedIdentityRow, TenantLink, TenantLinkRow,
    };
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ActedBy, Email, LinkedIdentityId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeSessionStore, Holder, test_caller_id,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::organization::{
        FakeLinkedIdentityLookup, OrgShape, org_shaped, org_store_with,
    };
    use crate::test_support::tenant::{
        FakeTenantStore, test_tenant_signing_in_with, test_tenant_with_id,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The address every caller [`FakeTenantAuthorities`] signs in has.
    const ANN: &str = "caller@example.test";

    fn link(tenant_id: TenantId, user_id: UserId) -> TenantLink {
        TenantLink::reconstitute(TenantLinkRow {
            tenant_id,
            user_id,
            email: Email::new(ANN).unwrap(),
            linked_at: clock::now(),
        })
        .unwrap()
    }

    fn identity(links: Vec<TenantLink>) -> LinkedIdentity {
        LinkedIdentity::reconstitute(LinkedIdentityRow {
            id: LinkedIdentityId::new(),
            organization_id: test_ctx().organization_id(),
            email: Email::new(ANN).unwrap(),
            links,
            created_at: clock::now(),
        })
        .unwrap()
    }

    /// Ann signed in to staging, her account in production linked to it.
    struct Fixture {
        production: TenantId,
        ann_there: UserId,
        identity: Option<LinkedIdentity>,
        users: FakeUserStore,
        enrollments: FakeMfaEnrollmentStore,
        production_mfa: MfaPolicy,
        authorities: FakeTenantAuthorities,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn linked() -> Self {
            let (production, ann_there) = (TenantId::new(), UserId::new());
            let staging = test_ctx().tenant_id();
            let users = FakeUserStore::empty();
            users.add_in(production, stored_user(ann_there, ANN, UserStatus::Active));
            Self {
                production,
                ann_there,
                identity: Some(identity(vec![
                    link(staging, test_caller_id()),
                    link(production, ann_there),
                ])),
                users,
                enrollments: FakeMfaEnrollmentStore::empty(),
                production_mfa: MfaPolicy::Disabled,
                authorities: FakeTenantAuthorities::holding(&[]),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn run(self, sessions: Arc<FakeSessionStore>) -> Result<LinkedSwitchSuccess, AppError> {
            let ctx = test_ctx();
            let staging = test_tenant_with_id(
                ctx.tenant_id(),
                ctx.organization_id(),
                "staging",
                "staging.com",
            );
            let production = self.production_tenant(&ctx);
            let owned = OrgShape::owning(&[ctx.tenant_id(), self.production]);
            let use_case = LinkedTenantSwitchUseCase::new(LinkedTenantSwitchPorts {
                tenant_authorities: Arc::new(self.authorities),
                organizations: org_store_with([org_shaped(ctx.organization_id(), owned)]),
                tenants: Arc::new(FakeTenantStore::holding_all([staging, production])),
                users: Arc::new(self.users),
                identities: Arc::new(self.identity.map_or_else(
                    FakeLinkedIdentityLookup::empty,
                    FakeLinkedIdentityLookup::with_identity,
                )),
                enrollments: Arc::new(self.enrollments),
                sessions,
                ..LinkedTenantSwitchPorts::fakes()
            });
            block_on(use_case.execute(&ctx, &test_auditor(self.audit), self.production))
        }

        /// Activates the target tenant with the arranged second-factor policy.
        fn production_tenant(&self, ctx: &CallerContext) -> Tenant {
            let mut production = test_tenant_signing_in_with(
                self.production,
                ctx.organization_id(),
                "production",
                TenantAuthSettings {
                    mfa_policy: self.production_mfa,
                    ..TenantAuthSettings::default()
                },
            );
            production.activate(ActedBy::Platform).unwrap();
            production
        }

        fn switch(self) -> Result<LinkedSwitchSuccess, AppError> {
            self.run(Arc::new(FakeSessionStore::empty()))
        }
    }

    /// Ann switches from staging to her linked account in production. A
    /// session opens there, under her production account, and is kept in
    /// production.
    #[test]
    fn the_switch_opens_a_session_on_the_linked_account() {
        let fixture = Fixture::linked();
        let (production, ann_there) = (fixture.production, fixture.ann_there);
        let sessions = Arc::new(FakeSessionStore::empty());

        let success = fixture.run(sessions.clone()).unwrap();

        assert_eq!(success.tenant_id, production);
        assert_eq!(success.user_id, ann_there);
        let saved = sessions.get_session(&success.session_id).unwrap();
        assert_eq!(*saved.user_id(), ann_there);
    }

    /// Ann switches to production. The record names both tenants and her
    /// production account by label.
    #[test]
    fn the_switch_record_names_both_tenants_and_the_account_by_label() {
        let fixture = Fixture::linked();
        let audit = fixture.audit.clone();

        fixture.switch().unwrap();

        let label = |key| audit.label_of("organization.tenant_switched", key);
        assert_eq!(label("source_tenant").as_deref(), Some("staging"));
        assert_eq!(label("target_tenant").as_deref(), Some("production"));
        assert_eq!(label("target_user").as_deref(), Some("Test User"));
    }

    /// Ann signed in to staging with only her password, and her production
    /// account has an authenticator app, which production lets its users
    /// use. The new session asks for its code.
    #[test]
    fn a_factor_on_the_linked_account_is_asked_for() {
        let mut fixture = Fixture::linked();
        fixture.production_mfa = MfaPolicy::Optional;
        fixture.enrollments = FakeMfaEnrollmentStore::active_for(Holder::in_tenant(
            fixture.production,
            fixture.ann_there,
        ));

        let success = fixture.switch().unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// Switching is forbidden when the identity has no account in the target tenant.
    #[test]
    fn a_tenant_without_a_linked_account_is_refused() {
        let mut fixture = Fixture::linked();
        fixture.identity = Some(identity(vec![link(
            test_ctx().tenant_id(),
            test_caller_id(),
        )]));

        let result = fixture.switch();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A caller without a linked identity receives not found, and no
    /// target session is created.
    #[test]
    fn a_caller_without_a_linked_identity_is_not_found() {
        let mut fixture = Fixture::linked();
        fixture.identity = None;
        let sessions = Arc::new(FakeSessionStore::empty());

        let result = fixture.run(sessions.clone());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(sessions.session_count(), 0);
    }

    /// A linked identity naming a different source account cannot authorize
    /// a switch solely through the shared address, and no session is created.
    #[test]
    fn a_shared_address_does_not_carry_another_users_link() {
        let mut fixture = Fixture::linked();
        fixture.identity = Some(identity(vec![
            link(test_ctx().tenant_id(), UserId::new()),
            link(fixture.production, fixture.ann_there),
        ]));
        let sessions = Arc::new(FakeSessionStore::empty());

        let result = fixture.run(sessions.clone());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(sessions.session_count(), 0);
    }

    /// A linked account pending address verification cannot be the target
    /// of a tenant switch.
    #[test]
    fn a_linked_account_without_its_verified_address_is_refused() {
        let mut fixture = Fixture::linked();
        let users = FakeUserStore::empty();
        users.add_in(
            fixture.production,
            stored_user(fixture.ann_there, ANN, UserStatus::PendingVerification),
        );
        fixture.users = users;

        let result = fixture.switch();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot authorize switching to a linked account.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::linked();
        fixture.authorities = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let result = fixture.switch();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
