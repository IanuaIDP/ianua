//! Signing in at an app's address with a password.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_trust::{
    DeviceSecret, PresentedSecret, SignInPlace,
};
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Email;

use crate::auditor::RequestAuditor;
use crate::email::LinkScope;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::{
    AppSignInCommon, OnTarget, Proved,
};
use crate::use_cases::authentication::app_sign_in::relay::target::Target;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::password::{
    ChangeToken, LoginAttempt, LoginTenant, TenantLoginOutcome, TenantLoginRequest,
    TenantLoginUseCase,
};

/// A password sign-in. Holds the password, so it has no `Debug`.
pub struct AppLogInRequest {
    /// The account's address.
    pub email: Email,
    /// The supplied secret checked against the account's credential.
    pub password: Secret,
    /// The secret of the device cookie the host keeps, when the browser
    /// remembered a device there.
    pub device: Option<DeviceSecret>,
    /// Where to send them afterwards, if they came from somewhere.
    pub return_to: Option<ReturnPath>,
}

/// Signs a person in at an app's address with a password.
pub struct AppLogInUseCase {
    common: Arc<AppSignInCommon>,
    tenant_login: Arc<TenantLoginUseCase>,
}

impl AppLogInUseCase {
    /// A use case signing in through the dashboard's own `tenant_login`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        tenant_login: Arc<TenantLoginUseCase>,
    ) -> Self {
        Self {
            common,
            tenant_login,
        }
    }
}

impl Command for AppLogInUseCase {
    type Caller = AppSignInContext;
    type Input = AppLogInRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Checks the password through the dashboard's own sign-in, then signs
    /// the person in on the app's host, asks for their second factor, has
    /// them confirm the sign-in from the link mailed to them, or, for a
    /// password an admin set or that expired, asks for a new one first.
    /// A device the browser remembered on this host skips the second factor
    /// as it does on the dashboard; one remembered anywhere else does not.
    ///
    /// The gateway's sign-in page carries no challenge yet, so while the
    /// tenant's sign-in is under high pressure this sign-in is refused with
    /// the challenge it needs, never let through without one.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or for invalid
    ///   credentials and a locked-out address alike.
    /// - `AppError::Forbidden` if the account must set up a second factor
    ///   first, or the workspace does not accept password sign-in, or not
    ///   from this address.
    /// - `AppError::EmailNotVerified` and `AppError::TenantUnavailable` as the
    ///   dashboard's own sign-in reports them.
    /// - `AppError::Internal` on persistence or signing failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppLogInRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let AppLogInRequest {
            email,
            password,
            device,
            return_to,
        } = request;
        let attempt = LoginAttempt {
            email,
            password,
            device_secret: device.map(|secret| device_on_host(&target, secret)),
            challenge: None,
            origin: ctx.origin(),
        };
        let login = TenantLoginRequest {
            tenant: on_app_host(&target),
            attempt,
        };
        let outcome = self.tenant_login.execute(&(), &auditor, login).await?;
        let on = OnTarget {
            ctx,
            target: &target,
        };
        continued(&self.common, &on, outcome, return_to).await
    }
}

/// Where a password sign-in on the app's host goes from `outcome`: on as
/// any proved sign-in does, or to the new password it owes, the change's
/// token for the host's challenge cookie.
///
/// # Errors
///
/// As [`AppSignInCommon::onward`] reports.
pub(in crate::use_cases::authentication::app_sign_in) async fn continued(
    common: &AppSignInCommon,
    on: &OnTarget<'_>,
    outcome: TenantLoginOutcome,
    return_to: Option<ReturnPath>,
) -> Result<AppSignInOutcome, AppError> {
    let success = match outcome {
        TenantLoginOutcome::SignedIn(success) => success,
        TenantLoginOutcome::PasswordChangeOwed(owed) => {
            let challenge = match owed.token {
                ChangeToken::HandedBack(token) => Some(token),
                ChangeToken::Mailed => None,
            };
            return Ok(AppSignInOutcome::PasswordChangeRequired {
                challenge,
                proof: owed.proof,
                reason: owed.reason,
                expires_at: owed.expires_at,
            });
        }
    };
    let proved = Proved {
        session_id: success.session_id,
        owed: success.second_factor,
        return_to,
    };
    common.onward(on, proved).await
}

/// The app's tenant as the dashboard's own sign-in takes it: already
/// resolved, with a link confirming the sign-in by email leading back to the
/// app's host.
pub(in crate::use_cases::authentication::app_sign_in) fn on_app_host(
    target: &Target,
) -> LoginTenant {
    LoginTenant::Resolved {
        org: Arc::clone(&target.org),
        tenant: Arc::clone(&target.tenant),
        confirm_at: LinkScope::app(&target.sign_in, target.host.clone()),
    }
}

/// The device cookie's `secret`, as presented on the app's host: a device
/// remembered on one app's host counts there alone, never on another
/// host, another tenant's app or the dashboard.
pub(in crate::use_cases::authentication::app_sign_in) fn device_on_host(
    target: &Target,
    secret: DeviceSecret,
) -> PresentedSecret {
    PresentedSecret::new(secret, SignInPlace::AppHost(target.host.clone()))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::authentication::credentials::breach::{BreachPolicy, BreachStatus};
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
    use ianua_domain::domains::authentication::credentials::password_rules::{
        ChangeReason, PasswordDue,
    };
    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authentication::device_trust::{
        TrustWindow, TrustedDevice, TrustedDeviceRow,
    };
    use ianua_domain::domains::authentication::methods::MfaPolicy;
    use ianua_domain::domains::authentication::mfa::owed::Enrolment;
    use ianua_domain::domains::authentication::operations::password_login::LoginCandidate;
    use ianua_domain::domains::authentication::recovery::change_proof::ChangeProof;
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::identity::account::address::AddressStanding;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::account::vouching::Vouching;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::password_policy::{ExpiryDays, PasswordExpiry, PasswordHygiene};
    use ianua_domain::types::{
        CidrRange, DomainName, Fact, HttpsUrl, IpAddress, Label, Lifetime, PasswordPolicy,
        PrincipalId, ServiceId, TrustedDeviceId, UserAgent, UserId,
    };

    use super::*;
    use crate::ports::TenantScoped;
    use crate::ports::authentication::UserLookup;
    use crate::ports::shared::MailSetup;
    use crate::services::authentication::sign_in_counts::SignInCounts;
    use crate::tenancy::ScopedTenant;
    use crate::test_support::authentication::{
        FakeAppSessionTokens, FakeBreachChecker, FakeMfaChallengeStore, FakeResetRequestStore,
        FakeSessionStore, FakeTrustedDeviceStore, SHOP_HOST, app_sign_in_lifetimes,
        app_sign_in_services, app_sign_in_target_ports, cross_host_ctx, lockout,
        shop_with_app_sign_in,
    };
    use crate::test_support::identity::{FakeUserStore, RecordingCredentialStore};
    use crate::test_support::oauth::hash_of;
    use crate::test_support::organization::{org_store_with, test_org};
    use crate::test_support::tenant::{FakeTenantStore, tenant_store_signing_in_with};
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::authentication::app_sign_in::{
        AppChangePasswordRequest, AppChangePasswordUseCase, SignInPorts,
    };
    use crate::use_cases::authentication::password::sign_in::due::DuePorts;
    use crate::use_cases::authentication::password::{
        ChangeDuePorts, ChangeDueUseCase, ConfirmationLinkPolicy, ConfirmationMailPorts,
        LoginPorts, LoginSecurityPorts, LoginSettings, LoginUseCase, ReplacementPorts,
        SecurityRules, TenantChangeDueUseCase, TenantLoginPorts,
    };

    const BOB: &str = "bob@acme.test";
    const PASSWORD: &str = "correct";
    const LAPTOP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CHOSEN: &str = "Quiet harbour at 6 bells";

    struct Fixture {
        use_case: AppLogInUseCase,
        change: AppChangePasswordUseCase,
        shop: ServiceId,
        sessions: Arc<FakeSessionStore>,
        tokens: Arc<FakeAppSessionTokens>,
        challenges: Arc<FakeMfaChallengeStore>,
    }

    /// Bob's account as sign-in finds it, with the password the credential
    /// store holds now, so a password he changes signs him in.
    struct BobsAccount {
        user_id: UserId,
        enrolment: Enrolment,
        credentials: Arc<RecordingCredentialStore>,
    }

    impl TenantScoped for BobsAccount {}

    #[async_trait]
    impl UserLookup for BobsAccount {
        async fn find_by_email(
            &self,
            _: &ScopedTenant,
            email: &Email,
        ) -> Result<Option<LoginCandidate>, DomainError> {
            if email.as_str() != BOB {
                return Ok(None);
            }
            Ok(self
                .credentials
                .hash_of(&self.user_id)
                .map(|password_hash| LoginCandidate {
                    user_id: self.user_id,
                    password_hash,
                    status: UserStatus::Active,
                    email_standing: AddressStanding::Verified,
                    enrolment: self.enrolment,
                    vouching: Vouching::Absent,
                    password_due: PasswordDue::Current,
                }))
        }
    }

    fn deployment_rules() -> LoginSettings {
        LoginSettings {
            security: SecurityRules {
                breach_policy: BreachPolicy::StepUp,
                device_trust: TrustWindow::standard(),
            },
            confirmation: ConfirmationLinkPolicy {
                lifetime: Lifetime::seconds(900).unwrap(),
                base_url: HttpsUrl::new("https://app.acme.test").unwrap(),
            },
        }
    }

    /// The tenant asks a second factor of everyone when Bob has one, so his
    /// sign-in owes it; otherwise it leaves factors optional.
    fn mfa_policy_for(enrolment: Enrolment) -> MfaPolicy {
        match enrolment {
            Enrolment::Enrolled => MfaPolicy::Required,
            Enrolment::NotEnrolled => MfaPolicy::Optional,
        }
    }

    /// Bob, with `enrolment`, whose password the breach check answers with
    /// `breach`.
    struct Bob {
        enrolment: Enrolment,
        breach: BreachStatus,
    }

    /// Who set Bob's password, and whether it is past Acme's thirty days.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum PasswordSetBy {
        Bob,
        BobLongAgo,
        Admin,
    }

    /// When Acme asks a second factor: of everyone holding one, or only of
    /// a device nobody remembered.
    #[derive(Clone, Copy)]
    enum FactorRules {
        ByEnrolment,
        NewDevicesOnly,
    }

    /// Whose a remembered laptop is.
    #[derive(Clone, Copy)]
    enum LaptopOf {
        Bob,
        Ann,
    }

    /// A laptop remembered on `remembered_on` by whom `held_by` says, its
    /// secret [`LAPTOP`], standing as `status` says.
    struct Laptop {
        remembered_on: &'static str,
        held_by: LaptopOf,
        status: DeviceStatus,
    }

    /// Acme's workspace around Bob: the addresses it takes sign-in from,
    /// none listed meaning any, who set his password, when it asks a second
    /// factor, and the laptops remembered.
    struct Workspace {
        allowlist: Vec<CidrRange>,
        password_set_by: PasswordSetBy,
        mail: Arc<dyn MailSetup>,
        factors: FactorRules,
        laptops: Vec<Laptop>,
    }

    impl Workspace {
        fn open() -> Self {
            Self {
                allowlist: Vec::new(),
                password_set_by: PasswordSetBy::Bob,
                mail: Fake::fake(),
                factors: FactorRules::ByEnrolment,
                laptops: Vec::new(),
            }
        }

        /// A second factor only for a device nobody remembered, with
        /// `laptop` remembered.
        fn remembering(laptop: Laptop) -> Self {
            Self {
                factors: FactorRules::NewDevicesOnly,
                laptops: vec![laptop],
                ..Self::open()
            }
        }

        /// Sam, an admin, set Bob's password, on a deployment whose mail is
        /// set up as `mail` says.
        fn set_by_sam(mail: Arc<dyn MailSetup>) -> Self {
            Self {
                password_set_by: PasswordSetBy::Admin,
                mail,
                ..Self::open()
            }
        }

        /// Bob chose his password long ago, past Acme's thirty days, on a
        /// deployment whose mail is set up as `mail` says.
        fn expired(mail: Arc<dyn MailSetup>) -> Self {
            Self {
                password_set_by: PasswordSetBy::BobLongAgo,
                mail,
                ..Self::open()
            }
        }
    }

    fn credentials_of(user_id: UserId, set_by: PasswordSetBy) -> Arc<RecordingCredentialStore> {
        let held = RecordingCredentialStore::holding(user_id, &FakeHasher.hash(PASSWORD).unwrap());
        match set_by {
            PasswordSetBy::Bob => Arc::new(held),
            PasswordSetBy::BobLongAgo => Arc::new(held.changed_seconds_ago(31 * 86_400)),
            PasswordSetBy::Admin => Arc::new(held.set_by_admin(user_id)),
        }
    }

    /// Acme's passwords last thirty days.
    fn thirty_days() -> PasswordPolicy {
        PasswordPolicy::default().with_hygiene(PasswordHygiene {
            expiry: PasswordExpiry::After(ExpiryDays::new(30).unwrap()),
            ..PasswordHygiene::default()
        })
    }

    /// The dashboard's own password sign-in over Bob's account, and the
    /// change a sign-in of his may owe, sharing its stores.
    fn tenant_login(
        sessions: Arc<FakeSessionStore>,
        bob_is: &Bob,
        workspace: &Workspace,
    ) -> (Arc<TenantLoginUseCase>, Arc<TenantChangeDueUseCase>) {
        let stores = SignInStores::new(sessions, bob_is, workspace);
        let login = Arc::new(LoginUseCase::new(
            stores.login_ports(bob_is, workspace),
            deployment_rules(),
        ));
        let change = Arc::new(ChangeDueUseCase::new(
            lockout(),
            stores.change_ports(&workspace.mail),
            Arc::clone(&login),
        ));
        let ports = TenantLoginPorts {
            org_store: org_store_with([test_org(test_ctx().organization_id(), "acme")]),
            tenant_store: stores.tenants,
            user_store: stores.users,
        };
        let tenant_login = Arc::new(TenantLoginUseCase::new(login, ports));
        let change_due = Arc::new(TenantChangeDueUseCase::new(
            change,
            Arc::clone(&tenant_login),
        ));
        (tenant_login, change_due)
    }

    /// Password sign-in and forced changes share Bob's records and session storage.
    struct SignInStores {
        user_id: UserId,
        users: Arc<FakeUserStore>,
        credentials: Arc<RecordingCredentialStore>,
        resets: Arc<FakeResetRequestStore>,
        sessions: Arc<FakeSessionStore>,
        tenants: Arc<FakeTenantStore>,
        attempts: SignInCounts,
    }

    impl SignInStores {
        /// Prepares Bob's account under the workspace's password and factor rules.
        fn new(sessions: Arc<FakeSessionStore>, bob: &Bob, workspace: &Workspace) -> Self {
            let user_id = UserId::new();
            let (mfa_policy, step_up_policy) = match workspace.factors {
                FactorRules::ByEnrolment => {
                    (mfa_policy_for(bob.enrolment), StepUpPolicy::relaxed())
                }
                FactorRules::NewDevicesOnly => {
                    (MfaPolicy::Optional, StepUpPolicy::untrusted_devices())
                }
            };
            Self {
                user_id,
                users: Arc::new(FakeUserStore::with_user(user_id, BOB)),
                credentials: credentials_of(user_id, workspace.password_set_by),
                resets: Arc::new(FakeResetRequestStore::empty()),
                sessions,
                tenants: tenant_store_signing_in_with(TenantAuthSettings {
                    mfa_policy,
                    step_up_policy,
                    ip_allowlist: workspace.allowlist.clone(),
                    password_policy: thirty_days(),
                    ..TenantAuthSettings::default()
                }),
                attempts: SignInCounts::fakes(),
            }
        }

        /// Both flows use the same password reset and mail state.
        fn due(&self, mail: &Arc<dyn MailSetup>) -> DuePorts {
            DuePorts {
                credentials: self.credentials.clone(),
                reset_store: self.resets.clone(),
                mail: mail.clone(),
                ..DuePorts::fakes()
            }
        }

        /// The login reads Bob's current credentials and the workspace's remembered devices.
        fn login_ports(&self, bob: &Bob, workspace: &Workspace) -> LoginPorts {
            LoginPorts {
                tenants: self.tenants.clone(),
                user_lookup: Arc::new(BobsAccount {
                    user_id: self.user_id,
                    enrolment: bob.enrolment,
                    credentials: self.credentials.clone(),
                }),
                attempts: self.attempts.clone(),
                sessions: self.sessions.clone(),
                security: self.security(bob.breach, &workspace.laptops),
                confirmation: ConfirmationMailPorts {
                    mail: workspace.mail.clone(),
                    ..ConfirmationMailPorts::fakes()
                },
                password_due: self.due(&workspace.mail),
                ..LoginPorts::fakes()
            }
        }

        /// Breach checks and remembered devices use Bob's existing account identity.
        fn security(&self, breach: BreachStatus, laptops: &[Laptop]) -> LoginSecurityPorts {
            LoginSecurityPorts {
                users: self.users.clone(),
                breach_checker: Arc::new(FakeBreachChecker { status: breach }),
                devices: Arc::new(FakeTrustedDeviceStore::holding(
                    laptops
                        .iter()
                        .map(|laptop| remembered(laptop, self.user_id)),
                )),
                ..LoginSecurityPorts::fakes()
            }
        }

        /// A required password change updates the same credentials the next login reads.
        fn change_ports(&self, mail: &Arc<dyn MailSetup>) -> ChangeDuePorts {
            ChangeDuePorts {
                reset_store: self.resets.clone(),
                replacement: ReplacementPorts {
                    user_store: self.users.clone(),
                    credential_store: self.credentials.clone(),
                    session_store: self.sessions.clone(),
                    tenant_store: self.tenants.clone(),
                    ..ReplacementPorts::fakes()
                },
                attempts: self.attempts.clone(),
                due: self.due(mail),
                ..ChangeDuePorts::fakes()
            }
        }
    }

    fn fixture(enrolment: Enrolment) -> Fixture {
        fixture_for(&Bob {
            enrolment,
            breach: BreachStatus::Clean,
        })
    }

    fn fixture_for(bob_is: &Bob) -> Fixture {
        fixture_in(bob_is, &Workspace::open())
    }

    fn fixture_in(bob_is: &Bob, workspace: &Workspace) -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let sessions = Arc::new(FakeSessionStore::empty());
        let tokens = Arc::new(FakeAppSessionTokens::default());
        let challenges = Arc::new(FakeMfaChallengeStore::default());
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            session_store: sessions.clone(),
            tokens: tokens.clone(),
            challenge_store: challenges.clone(),
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = Arc::new(AppSignInCommon::new(ports, base, app_sign_in_lifetimes()));
        let (tenant_login, change_due) = tenant_login(sessions.clone(), bob_is, workspace);
        Fixture {
            use_case: AppLogInUseCase::new(Arc::clone(&common), tenant_login),
            change: AppChangePasswordUseCase::new(common, change_due),
            shop: shop_id,
            sessions,
            tokens,
            challenges,
        }
    }

    fn log_in(f: &Fixture, password: &str) -> Result<AppSignInOutcome, AppError> {
        log_in_at(f, password, &cross_host_ctx(f.shop, SHOP_HOST))
    }

    fn log_in_at(
        f: &Fixture,
        password: &str,
        ctx: &AppSignInContext,
    ) -> Result<AppSignInOutcome, AppError> {
        log_in_with(f, password, ctx, None)
    }

    fn log_in_with(
        f: &Fixture,
        password: &str,
        ctx: &AppSignInContext,
        device: Option<DeviceSecret>,
    ) -> Result<AppSignInOutcome, AppError> {
        let request = AppLogInRequest {
            email: Email::new(BOB).unwrap(),
            password: Secret::new(password),
            device,
            return_to: None,
        };
        block_on(f.use_case.execute(
            ctx,
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))
    }

    /// Bob's sign-in on the shop from the browser holding the device cookie
    /// [`LAPTOP`].
    fn from_his_laptop(f: &Fixture) -> Result<AppSignInOutcome, AppError> {
        let ctx = cross_host_ctx(f.shop, SHOP_HOST);
        log_in_with(f, PASSWORD, &ctx, Some(DeviceSecret::new(LAPTOP).unwrap()))
    }

    /// The laptop `laptop` describes, as its record holds it, Bob being
    /// `bob`.
    fn remembered(laptop: &Laptop, bob: UserId) -> TrustedDevice<ResolvedTenant> {
        let held_by = match laptop.held_by {
            LaptopOf::Bob => bob,
            LaptopOf::Ann => UserId::new(),
        };
        let host = DomainName::new(laptop.remembered_on).unwrap();
        let secret = PresentedSecret::new(
            DeviceSecret::new(LAPTOP).unwrap(),
            SignInPlace::AppHost(host),
        );
        let now = clock::now();
        TrustedDevice::reconstitute(TrustedDeviceRow {
            id: TrustedDeviceId::new(),
            subject_id: PrincipalId::from(held_by),
            secret_hash: hash_of(secret.bound().expose()),
            device_name: Label::new("device_name", "Bob's laptop").unwrap(),
            last_user_agent: UserAgent::new("Mozilla/5.0").unwrap(),
            last_ip: IpAddress::new("203.0.113.7").unwrap(),
            status: laptop.status,
            last_seen_at: now,
            created_at: now,
        })
        .unwrap()
    }

    fn bobs_laptop_on(host: &'static str, status: DeviceStatus) -> Laptop {
        Laptop {
            remembered_on: host,
            held_by: LaptopOf::Bob,
            status,
        }
    }

    /// Bob remembered his laptop on the shop's host. Signing in there from
    /// it skips the second factor, and the session names the laptop, so
    /// the shop's session token carries it to a device posture check.
    #[test]
    fn a_device_remembered_on_this_host_skips_the_second_factor() {
        let f = fixture_in(
            &enrolled_bob(),
            &Workspace::remembering(bobs_laptop_on(SHOP_HOST, DeviceStatus::Trusted)),
        );

        let outcome = from_his_laptop(&f).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::SignedIn { .. }));
        let named = f.tokens.named_devices.lock().unwrap().clone();
        assert_eq!(named.len(), 1);
        assert!(matches!(named[0], Fact::Known(_)));
    }

    /// A device remembered on the billing host still requires Bob's second
    /// factor when its cookie is presented on the shop.
    #[test]
    fn a_device_remembered_on_another_host_does_not_count_here() {
        let f = fixture_in(
            &enrolled_bob(),
            &Workspace::remembering(bobs_laptop_on("billing.acme.test", DeviceStatus::Trusted)),
        );

        let outcome = from_his_laptop(&f).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::MfaRequired { .. }));
    }

    /// A revoked laptop's cookie cannot skip Bob's second factor on the shop.
    #[test]
    fn a_revoked_device_does_not_count() {
        let f = fixture_in(
            &enrolled_bob(),
            &Workspace::remembering(bobs_laptop_on(SHOP_HOST, DeviceStatus::Revoked)),
        );

        let outcome = from_his_laptop(&f).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::MfaRequired { .. }));
    }

    /// Ann's remembered-device cookie cannot skip Bob's second factor when
    /// signing in to his account.
    #[test]
    fn someone_elses_device_does_not_count() {
        let f = fixture_in(
            &enrolled_bob(),
            &Workspace::remembering(Laptop {
                remembered_on: SHOP_HOST,
                held_by: LaptopOf::Ann,
                status: DeviceStatus::Trusted,
            }),
        );

        let outcome = from_his_laptop(&f).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::MfaRequired { .. }));
    }

    fn enrolled_bob() -> Bob {
        Bob {
            enrolment: Enrolment::Enrolled,
            breach: BreachStatus::Clean,
        }
    }

    fn not_enrolled() -> Bob {
        Bob {
            enrolment: Enrolment::NotEnrolled,
            breach: BreachStatus::Clean,
        }
    }

    /// Bob signs in on the shop with his password. A session cookie is
    /// minted for the shop's host and he lands where the shop sends people.
    #[test]
    fn the_right_password_signs_in_on_the_host() {
        let f = fixture(Enrolment::NotEnrolled);

        let outcome = log_in(&f, PASSWORD).unwrap();

        let AppSignInOutcome::SignedIn { return_to, .. } = outcome else {
            panic!("Bob is signed in");
        };
        assert_eq!(return_to.as_str(), "/");
        assert_eq!(
            f.tokens.minted.lock().unwrap().as_slice(),
            [format!("session:{SHOP_HOST}:shop")]
        );
    }

    /// Bob has a second factor. His password opens a challenge for it
    /// rather than a session cookie.
    #[test]
    fn an_enrolled_person_is_asked_for_the_second_factor() {
        let f = fixture(Enrolment::Enrolled);

        let outcome = log_in(&f, PASSWORD).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::MfaRequired { .. }));
        assert_eq!(f.challenges.count(), 1);
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// Bob's password turns up in a breach and he has no second factor. His
    /// sign-in waits for him to confirm it from his mailbox: the shop's host
    /// gets a challenge cookie holding it, and no session cookie.
    #[test]
    fn a_sign_in_owing_a_mailbox_confirmation_is_held_by_a_challenge() {
        let f = fixture_for(&Bob {
            enrolment: Enrolment::NotEnrolled,
            breach: BreachStatus::Breached(42),
        });

        let outcome = log_in(&f, PASSWORD).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::ConfirmByEmail { .. }));
        assert_eq!(f.challenges.count(), 1);
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// A breached password with neither a factor nor mail is refused with
    /// a new-invitation instruction. No challenge is stored and no session
    /// cookie is minted.
    #[test]
    fn a_breached_password_with_no_factor_or_mail_is_refused() {
        let f = fixture_in(
            &Bob {
                enrolment: Enrolment::NotEnrolled,
                breach: BreachStatus::Breached(42),
            },
            &Workspace {
                mail: FakeMailSetup::not_set_up(),
                ..Workspace::open()
            },
        );

        let outcome = log_in(&f, PASSWORD);

        assert!(matches!(
            outcome,
            Err(AppError::Forbidden(message)) if message.as_str().contains("new invitation")
        ));
        assert_eq!(f.challenges.count(), 0);
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// A wrong shop password returns not found and mints no session cookie.
    #[test]
    fn a_wrong_password_is_refused() {
        let f = fixture(Enrolment::NotEnrolled);

        let outcome = log_in(&f, "guess");

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// After ten wrong shop passwords, even the right password is refused,
    /// and no session cookie is minted.
    #[test]
    fn a_locked_out_address_is_refused_even_with_the_right_password() {
        let f = fixture(Enrolment::NotEnrolled);
        for _ in 0..10 {
            let _ = log_in(&f, "guess");
        }

        let outcome = log_in(&f, PASSWORD);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// A password sign-in naming an unknown service returns not found on
    /// the shop's host.
    #[test]
    fn a_service_without_app_sign_in_here_is_not_found() {
        let f = fixture(Enrolment::NotEnrolled);
        let request = AppLogInRequest {
            email: Email::new(BOB).unwrap(),
            password: Secret::new(PASSWORD),
            device: None,
            return_to: None,
        };
        let ctx = cross_host_ctx(ServiceId::new(), SHOP_HOST);

        let outcome = block_on(f.use_case.execute(
            &ctx,
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ));

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
    }

    /// A correct password from outside the workspace's allowed network is
    /// refused without creating a session or minting a cookie.
    #[test]
    fn a_sign_in_from_outside_the_allowlist_is_refused() {
        let office_only = Workspace {
            allowlist: vec![CidrRange::new("198.51.100.0/24").unwrap()],
            ..Workspace::open()
        };
        let f = fixture_in(&not_enrolled(), &office_only);
        let from_elsewhere = AppSignInContext {
            ip_address: Some(IpAddress::new("203.0.113.9").unwrap()),
            ..cross_host_ctx(f.shop, SHOP_HOST)
        };

        let outcome = log_in_at(&f, PASSWORD, &from_elsewhere);

        assert!(matches!(outcome, Err(AppError::Forbidden(_))));
        assert_eq!(f.sessions.session_count(), 0);
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// Bob sets a new password on the shop with the token his sign-in
    /// handed back.
    fn change(
        f: &Fixture,
        challenge: Secret,
        password: &str,
    ) -> Result<AppSignInOutcome, AppError> {
        let request = AppChangePasswordRequest {
            challenge,
            new_password: Secret::new(password),
            code: None,
            device: None,
            return_to: None,
        };
        block_on(f.change.execute(
            &cross_host_ctx(f.shop, SHOP_HOST),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))
    }

    /// The change token Bob's sign-in handed back for his expired password,
    /// for the host's challenge cookie.
    fn change_owed(outcome: AppSignInOutcome) -> Secret {
        let AppSignInOutcome::PasswordChangeRequired {
            challenge, reason, ..
        } = outcome
        else {
            panic!("Bob's sign-in owes a new password");
        };
        assert_eq!(reason, ChangeReason::Expired);
        challenge.expect("the token comes back to the host")
    }

    /// An admin-set password requires mailed-link proof and returns no
    /// change challenge to the browser. No session opens and no cookie is minted.
    #[test]
    fn a_password_sam_set_is_changed_through_bobs_mailbox() {
        let f = fixture_in(&not_enrolled(), &Workspace::set_by_sam(Fake::fake()));

        let outcome = log_in(&f, PASSWORD).unwrap();

        let AppSignInOutcome::PasswordChangeRequired {
            challenge, proof, ..
        } = outcome
        else {
            panic!("Bob's sign-in owes a new password");
        };
        assert!(challenge.is_none());
        assert_eq!(proof, ChangeProof::MailedLink);
        assert_eq!(f.sessions.session_count(), 0);
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// An admin-set password with neither mail nor a factor is refused with
    /// an invitation instruction, and no session cookie is minted.
    #[test]
    fn a_password_sam_set_is_refused_with_no_mail_and_no_factor() {
        let f = fixture_in(
            &not_enrolled(),
            &Workspace::set_by_sam(FakeMailSetup::not_set_up()),
        );

        let result = log_in(&f, PASSWORD);

        assert!(
            matches!(result, Err(AppError::Forbidden(ref why)) if why.as_str().contains("invitation"))
        );
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// Bob's own password expired. His sign-in on the shop opens no
    /// session; the host is handed the change's token for its challenge
    /// cookie.
    #[test]
    fn an_expired_password_opens_no_session_on_the_host() {
        let f = fixture_in(&not_enrolled(), &Workspace::expired(Fake::fake()));

        let challenge = change_owed(log_in(&f, PASSWORD).unwrap());

        assert!(!challenge.expose().is_empty());
        assert_eq!(f.sessions.session_count(), 0);
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// Bob sets a new password with the token his sign-in on the shop handed
    /// back. The sign-in finishes on the shop's host with a session cookie.
    #[test]
    fn a_new_password_finishes_the_sign_in_on_the_host() {
        let f = fixture_in(&not_enrolled(), &Workspace::expired(Fake::fake()));
        let challenge = change_owed(log_in(&f, PASSWORD).unwrap());

        let outcome = change(&f, challenge, CHOSEN).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::SignedIn { .. }));
        assert_eq!(
            f.tokens.minted.lock().unwrap().as_slice(),
            [format!("session:{SHOP_HOST}:shop")]
        );
    }

    /// The same on a deployment with no mail server: the change is owed
    /// inside the sign-in and finishes it, with nothing waiting for a mail.
    #[test]
    fn a_new_password_finishes_the_sign_in_where_nothing_is_mailed() {
        let f = fixture_in(
            &not_enrolled(),
            &Workspace::expired(FakeMailSetup::not_set_up()),
        );
        let challenge = change_owed(log_in(&f, PASSWORD).unwrap());

        let outcome = change(&f, challenge, CHOSEN).unwrap();

        assert!(matches!(outcome, AppSignInOutcome::SignedIn { .. }));
    }

    /// Replaying a change token after it finishes Bob's sign-in returns not
    /// found and leaves the minted-cookie count at one.
    #[test]
    fn a_change_token_finishes_one_sign_in() {
        let f = fixture_in(&not_enrolled(), &Workspace::expired(Fake::fake()));
        let challenge = change_owed(log_in(&f, PASSWORD).unwrap());
        let replayed = Secret::new(challenge.expose());
        change(&f, challenge, CHOSEN).unwrap();

        let again = change(&f, replayed, "Another quiet river 7");

        assert!(matches!(again, Err(AppError::NotFound(_))));
        assert_eq!(f.tokens.minted.lock().unwrap().len(), 1);
    }
}
