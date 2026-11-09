//! Signing a tenant user in with a password, for a tenant named by the
//! slugs in the address or already resolved by the caller.
//!
//! An unknown organization or tenant answers like a wrong password, so the
//! slugs cannot be used to find out which tenants exist. The password
//! sign-in itself is [`LoginUseCase`]'s.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_trust::PresentedSecret;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::risk_engine::challenge::ChallengeProof;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Email, SessionId, TenantId, TenantSlug, UserId};

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::refused::invalid_credentials;
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::password::sign_in::due::PasswordChangeOwed;
use crate::use_cases::authentication::password::sign_in::login::LoginOutcome;
use crate::use_cases::authentication::password::{LoginRequest, LoginSuccess, LoginUseCase};

/// A password sign-in to a tenant.
pub struct TenantLoginRequest {
    /// The tenant the person signs in to.
    pub tenant: LoginTenant,
    /// What the person presented.
    pub attempt: LoginAttempt,
}

/// The tenant a password sign-in is for.
pub enum LoginTenant {
    /// Named by the slugs in the address. An unknown pair reads as bad
    /// credentials.
    Named {
        /// The organization's slug.
        org_slug: TenantSlug,
        /// The tenant's slug.
        tenant_slug: TenantSlug,
    },
    /// Already resolved by the caller, with its organization and where a
    /// confirmation link for the sign-in lands.
    Resolved {
        /// The tenant's organization.
        org: Arc<Organization>,
        /// The resolved destination whose sign-in policy applies.
        tenant: Arc<Tenant>,
        /// Where a link confirming the sign-in by email lands.
        confirm_at: LinkScope,
    },
}

/// What a person presents to sign in, and from where.
pub struct LoginAttempt {
    /// The address to sign in with.
    pub email: Email,
    /// The password as typed.
    pub password: Secret,
    /// The secret of a browser the person remembered, if it sent one.
    pub device_secret: Option<PresentedSecret>,
    /// The proof of a passed challenge, if the browser solved one.
    pub challenge: Option<ChallengeProof>,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// A password sign-in to a tenant that opened a session.
pub struct TenantLoginSuccess {
    /// The persisted sign-in opened by the accepted password.
    pub session_id: SessionId,
    /// The raw refresh token.
    pub refresh_token: Secret,
    /// What the sign-in still owes in the way of a second factor.
    pub second_factor: SecondFactor,
    /// The tenant signed in to.
    pub tenant_id: TenantId,
    /// The tenant's display name.
    pub tenant_name: String,
    /// The person's display name, or empty when it cannot be read.
    pub display_name: String,
}

/// How a password sign-in to a tenant ended, short of a refusal.
pub enum TenantLoginOutcome {
    /// A session opened, owing whatever second factor the sign-in asks.
    SignedIn(TenantLoginSuccess),
    /// The password was right, but an admin set it or it expired. No
    /// session opened; a new password set with the change's token, through
    /// [`TenantChangeDueUseCase`](crate::use_cases::authentication::password::TenantChangeDueUseCase),
    /// finishes the sign-in.
    PasswordChangeOwed(PasswordChangeOwed),
}

/// The ports [`TenantLoginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct TenantLoginPorts {
    /// Finds the organization by its slug.
    pub org_store: Arc<dyn OrganizationStore>,
    /// Finds the tenant by its slug in the organization.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The tenant's users, for the display name.
    pub user_store: Arc<dyn UserStore>,
}

/// Signs a tenant user in with a password.
pub struct TenantLoginUseCase {
    login: Arc<LoginUseCase>,
    ports: TenantLoginPorts,
}

/// The tenant resolved, its organization, and where a confirmation lands.
pub(super) struct Destination {
    /// The tenant's organization.
    pub(super) org: Arc<Organization>,
    /// The resolved destination whose sign-in policy applies.
    pub(super) tenant: Arc<Tenant>,
    /// Where a link confirming the sign-in lands.
    pub(super) confirm_at: LinkScope,
}

impl TenantLoginUseCase {
    /// A use case resolving tenants through `ports` and signing in through
    /// `login`.
    #[must_use]
    pub fn new(login: Arc<LoginUseCase>, ports: TenantLoginPorts) -> Self {
        Self { login, ports }
    }

    /// The organization and tenant the sign-in is for, resolving slugs when
    /// the caller named it by them.
    pub(super) async fn resolved(&self, tenant: LoginTenant) -> Result<Destination, AppError> {
        match tenant {
            LoginTenant::Resolved {
                org,
                tenant,
                confirm_at,
            } => Ok(Destination {
                org,
                tenant,
                confirm_at,
            }),
            LoginTenant::Named {
                org_slug,
                tenant_slug,
            } => self.named(org_slug, tenant_slug).await,
        }
    }

    /// The organization and tenant named by their slugs.
    async fn named(
        &self,
        org_slug: TenantSlug,
        tenant_slug: TenantSlug,
    ) -> Result<Destination, AppError> {
        let org = self
            .ports
            .org_store
            .find_by_slug(&org_slug)
            .await
            .or_internal()?
            .ok_or_else(invalid_credentials)?;
        let tenant = self
            .ports
            .tenant_store
            .find_by_slug_in_org(&tenant_slug, org.id())
            .await
            .or_internal()?
            .ok_or_else(invalid_credentials)?;
        Ok(Destination {
            org,
            tenant,
            confirm_at: LinkScope::tenant(org_slug, tenant_slug),
        })
    }

    /// The display name of the person signed in, or empty when it cannot be
    /// read: the sign-in already succeeded.
    async fn display_name(&self, tenant: &ScopedTenant, user_id: &UserId) -> String {
        self.ports
            .user_store
            .find_by_id(tenant, user_id)
            .await
            .ok()
            .flatten()
            .map(|user| user.display_name().as_str().to_owned())
            .unwrap_or_default()
    }
}

impl Command for TenantLoginUseCase {
    type Caller = ();
    type Input = TenantLoginRequest;
    type Output = Result<TenantLoginOutcome, AppError>;

    /// Signs `request.attempt` in to the tenant `request.tenant` names, the
    /// record attributed to its organization and tenant. A right password
    /// an admin set or that expired opens no session and answers
    /// [`TenantLoginOutcome::PasswordChangeOwed`].
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` hides unknown slugs/addresses, wrong passwords, network lockout and account refusals alike.
    /// - `AppError::EmailNotVerified` for a right password with an unconfirmed address; `Forbidden` for refused origin, account state or risk.
    /// - `AppError::TenantUnavailable` for a closed tenant; `ChallengeRequired` under high pressure on an untrusted device without proof. Neither identifies accounts.
    /// - `AppError::Busy` when hashing cannot start in time; `Internal` on storage, mail or audit failure.
    async fn execute(
        &self,
        _: &(),
        auditor: &RequestAuditor,
        request: TenantLoginRequest,
    ) -> Result<TenantLoginOutcome, AppError> {
        let TenantLoginRequest { tenant, attempt } = request;
        let destination = self.resolved(tenant).await?;
        let scoped = ScopedTenant::from_registry(&destination.tenant);
        let attributed = auditor
            .with_organization(*destination.org.id())
            .with_tenant(*destination.tenant.id());
        let outcome = self
            .login
            .execute(&scoped, &attributed, login_request(attempt, &destination))
            .await
            .map_err(outward_refusal)?;
        self.told(outcome, &scoped, &destination.tenant).await
    }
}

impl TenantLoginUseCase {
    /// What the caller is told of `outcome` in `tenant`: the session with
    /// the person's name, or the change the sign-in owes.
    pub(super) async fn told(
        &self,
        outcome: LoginOutcome,
        scoped: &ScopedTenant,
        tenant: &Tenant,
    ) -> Result<TenantLoginOutcome, AppError> {
        let success = match outcome {
            LoginOutcome::SignedIn(success) => success,
            LoginOutcome::PasswordChangeOwed(owed) => {
                return Ok(TenantLoginOutcome::PasswordChangeOwed(owed));
            }
        };
        let display_name = self.display_name(scoped, &success.user_id).await;
        Ok(TenantLoginOutcome::SignedIn(signed_in(
            success,
            tenant,
            display_name,
        )))
    }
}

/// The password sign-in `attempt` asks for at `destination`.
fn login_request(attempt: LoginAttempt, destination: &Destination) -> LoginRequest {
    LoginRequest {
        email: attempt.email,
        password: attempt.password,
        device_secret: attempt.device_secret,
        challenge: attempt.challenge,
        origin: attempt.origin,
        confirm_at: destination.confirm_at.clone(),
    }
}

fn signed_in(success: LoginSuccess, tenant: &Tenant, display_name: String) -> TenantLoginSuccess {
    TenantLoginSuccess {
        session_id: success.session_id,
        refresh_token: success.refresh_token,
        second_factor: success.second_factor,
        tenant_id: *tenant.id(),
        tenant_name: tenant.display_name().as_str().to_owned(),
        display_name,
    }
}

/// What the caller is told about a refused sign-in. Refusals that say
/// something about the account only after its password was proven, about
/// the tenant, about the whole tenant's sign-in being under pressure, or
/// about the node or a fault on our side stand. Every other refusal, a
/// lockout included, reads as bad credentials.
fn outward_refusal(error: AppError) -> AppError {
    match error {
        AppError::EmailNotVerified
        | AppError::Forbidden(_)
        | AppError::TenantUnavailable(_)
        | AppError::ChallengeRequired(_)
        | AppError::Busy
        | AppError::Internal(_) => error,
        _ => invalid_credentials(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::BreachPolicy;
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
    use ianua_domain::domains::authentication::credentials::password_rules::PasswordDue;
    use ianua_domain::domains::authentication::device_trust::TrustWindow;
    use ianua_domain::domains::authentication::mfa::owed::Enrolment;
    use ianua_domain::domains::authentication::operations::password_login::LoginCandidate;
    use ianua_domain::domains::identity::account::address::AddressStanding;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::account::vouching::Vouching;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::domains::tenant::status::{PlatformHold, TenantStatus};
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::{CidrRange, Fact, HttpsUrl, IpAddress, Lifetime, OrganizationId};

    use super::*;
    use crate::test_support::authentication::FakeUserLookup;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::organization::{org_store_with, test_org};
    use crate::test_support::tenant::{
        FakeTenantStore, archived_tenant_for_ctx, tenant_store_in_status,
        tenant_store_signing_in_with, test_tenant_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::password::{
        ConfirmationLinkPolicy, LoginPorts, LoginSecurityPorts, LoginSettings, SecurityRules,
    };

    const BOB: &str = "bob@acme.com";
    const PASSWORD: &str = "correct";

    fn slug(value: &str) -> TenantSlug {
        TenantSlug::new(value, &DomainLimits::default().slug).unwrap()
    }

    fn bob_signs_in(user_id: UserId, standing: AddressStanding) -> FakeUserLookup {
        FakeUserLookup::holding([(
            Email::new(BOB).unwrap(),
            LoginCandidate {
                user_id,
                password_hash: FakeHasher.hash(PASSWORD).unwrap(),
                status: UserStatus::Active,
                email_standing: standing,
                enrolment: Enrolment::NotEnrolled,
                vouching: Vouching::Absent,
                password_due: PasswordDue::Current,
            },
        )])
    }

    fn settings() -> LoginSettings {
        LoginSettings {
            security: SecurityRules {
                breach_policy: BreachPolicy::Off,
                device_trust: TrustWindow::standard(),
            },
            confirmation: ConfirmationLinkPolicy {
                lifetime: Lifetime::seconds(900).unwrap(),
                base_url: HttpsUrl::new("https://app.acme.test").unwrap(),
            },
        }
    }

    /// Bob's account in the test tenant, his address standing as
    /// `standing` says, under `tenants`.
    fn use_case_for(
        tenants: Arc<FakeTenantStore>,
        standing: AddressStanding,
    ) -> TenantLoginUseCase {
        let bob = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(bob, BOB));
        let login = LoginUseCase::new(
            LoginPorts {
                tenants: tenants.clone(),
                user_lookup: Arc::new(bob_signs_in(bob, standing)),
                security: LoginSecurityPorts {
                    users: users.clone(),
                    ..LoginSecurityPorts::fakes()
                },
                ..LoginPorts::fakes()
            },
            settings(),
        );
        TenantLoginUseCase::new(
            Arc::new(login),
            TenantLoginPorts {
                org_store: org_store_with([test_org(test_ctx().organization_id(), "acme-corp")]),
                tenant_store: tenants,
                user_store: users,
            },
        )
    }

    fn use_case_in(tenants: Arc<FakeTenantStore>) -> TenantLoginUseCase {
        use_case_for(tenants, AddressStanding::Verified)
    }

    fn use_case() -> TenantLoginUseCase {
        use_case_in(tenant_store_signing_in_with(TenantAuthSettings {
            max_login_attempts: 3,
            ..TenantAuthSettings::default()
        }))
    }

    fn attempt(email: &str, password: &str) -> LoginAttempt {
        LoginAttempt {
            email: Email::new(email).unwrap(),
            password: Secret::new(password),
            device_secret: None,
            challenge: None,
            origin: ClientOrigin::default(),
        }
    }

    fn named(org: &str, tenant: &str, attempt: LoginAttempt) -> TenantLoginRequest {
        TenantLoginRequest {
            tenant: LoginTenant::Named {
                org_slug: slug(org),
                tenant_slug: slug(tenant),
            },
            attempt,
        }
    }

    fn req(tenant: &str, password: &str) -> TenantLoginRequest {
        named("acme-corp", tenant, attempt(BOB, password))
    }

    fn sign_in(
        use_case: &TenantLoginUseCase,
        request: TenantLoginRequest,
    ) -> Result<TenantLoginSuccess, AppError> {
        let outcome = block_on(use_case.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))?;
        match outcome {
            TenantLoginOutcome::SignedIn(success) => Ok(success),
            TenantLoginOutcome::PasswordChangeOwed(_) => {
                panic!("the sign-in owes a password change")
            }
        }
    }

    /// Bob signs in to the acme tenant with his password. A session opens
    /// and he gets a token.
    #[test]
    fn valid_credentials_return_success() {
        let success = sign_in(&use_case(), req("acme", PASSWORD)).unwrap();

        assert!(!success.refresh_token.expose().is_empty());
        assert_eq!(success.tenant_id, test_ctx().tenant_id());
    }

    /// Bob signs in, and the answer carries his display name and the
    /// tenant's, for the page that greets him.
    #[test]
    fn success_names_the_person_and_the_tenant() {
        let success = sign_in(&use_case(), req("acme", PASSWORD)).unwrap();

        assert_eq!(success.display_name, "Test User");
        assert_eq!(success.tenant_name, "Acme");
    }

    /// A wrong password is concealed behind the not-found response.
    #[test]
    fn wrong_password_returns_not_found() {
        let result = sign_in(&use_case(), req("acme", "wrong"));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A correct password for Bob's unconfirmed address returns the email-verification error.
    #[test]
    fn an_unconfirmed_address_is_told_so_rather_than_given_invalid_credentials() {
        let tenants = tenant_store_signing_in_with(TenantAuthSettings::default());
        let use_case = use_case_for(tenants, AddressStanding::Unverified);

        let result = sign_in(&use_case, req("acme", PASSWORD));

        assert!(matches!(result, Err(AppError::EmailNotVerified)));
    }

    /// A suspended tenant returns unavailable even for Bob's correct password.
    #[test]
    fn a_suspended_tenant_refuses_its_users() {
        let use_case = use_case_in(tenant_store_in_status(TenantStatus::Suspended));

        let result = sign_in(&use_case, req("acme", PASSWORD));

        assert!(matches!(result, Err(AppError::TenantUnavailable(_))));
    }

    /// An archived tenant refuses password sign-in as unavailable.
    #[test]
    fn an_archived_tenant_refuses_its_users() {
        let tenants = Arc::new(FakeTenantStore::holding(archived_tenant_for_ctx(
            1,
            PlatformHold::Free,
        )));

        let result = sign_in(&use_case_in(tenants), req("acme", PASSWORD));

        assert!(matches!(result, Err(AppError::TenantUnavailable(_))));
    }

    /// Correct and incorrect passwords both return unavailable for a suspended tenant.
    #[test]
    fn a_suspended_tenant_answers_the_same_whatever_the_password() {
        let use_case = use_case_in(tenant_store_in_status(TenantStatus::Suspended));

        let right = sign_in(&use_case, req("acme", PASSWORD));
        let wrong = sign_in(&use_case, req("acme", "wrong"));

        assert!(matches!(right, Err(AppError::TenantUnavailable(_))));
        assert!(matches!(wrong, Err(AppError::TenantUnavailable(_))));
    }

    /// An unknown tenant slug returns the not-found credential refusal.
    #[test]
    fn unknown_tenant_slug_returns_not_found() {
        let result = sign_in(&use_case(), req("nonexistent", PASSWORD));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An unknown organization slug returns the not-found credential refusal.
    #[test]
    fn unknown_org_slug_returns_not_found() {
        let result = sign_in(
            &use_case(),
            named("nonexistent-org", "acme", attempt(BOB, PASSWORD)),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Wrong passwords and unknown tenant or organization slugs return identical refusal messages.
    #[test]
    fn all_error_shapes_are_identical() {
        let use_case = use_case();

        let wrong_password = sign_in(&use_case, req("acme", "wrong"));
        let wrong_tenant = sign_in(&use_case, req("nonexistent", PASSWORD));
        let wrong_org = sign_in(
            &use_case,
            named("nonexistent-org", "acme", attempt(BOB, PASSWORD)),
        );

        let (Err(AppError::NotFound(a)), Err(AppError::NotFound(b)), Err(AppError::NotFound(c))) =
            (wrong_password, wrong_tenant, wrong_org)
        else {
            panic!("all are refused as invalid credentials");
        };
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    /// Three failed requests reach the tenant's attempt limit, after which
    /// the correct password also receives the not-found refusal.
    #[test]
    fn repeated_wrong_passwords_lock_the_guessers_network_across_requests() {
        let use_case = use_case();
        for _ in 0..3 {
            let failed = sign_in(&use_case, req("acme", "wrong"));
            assert!(matches!(failed, Err(AppError::NotFound(_))));
        }

        let result = sign_in(&use_case, req("acme", PASSWORD));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A request outside the tenant's network allowlist is forbidden even
    /// when Bob's password is correct.
    #[test]
    fn a_sign_in_from_outside_the_allowlist_is_refused() {
        let use_case = use_case_in(tenant_store_signing_in_with(TenantAuthSettings {
            ip_allowlist: vec![CidrRange::new("198.51.100.0/24").unwrap()],
            ..TenantAuthSettings::default()
        }));
        let from_elsewhere = LoginAttempt {
            origin: ClientOrigin {
                ip_address: Fact::Known(IpAddress::new("203.0.113.9").unwrap()),
                user_agent: None,
            },
            ..attempt(BOB, PASSWORD)
        };

        let result = sign_in(&use_case, named("acme-corp", "acme", from_elsewhere));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Looking up a tenant under another organization returns not found.
    #[test]
    fn tenant_from_wrong_org_returns_not_found() {
        let tenants = Arc::new(FakeTenantStore::holding(test_tenant_in(
            OrganizationId::new(),
            "acme",
            "acme.com",
        )));

        let result = sign_in(&use_case_in(tenants), req("acme", PASSWORD));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
