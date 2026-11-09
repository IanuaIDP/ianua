//! Binding to the directory: an LDAP simple bind, checked as a sign-in.
//!
//! LDAP has no sessions, so each bind proves the person again and opens
//! none. The domain asks for two things ([`DirectoryBind`]): the account's
//! password, and a client certificate in force for the account, presented
//! on the connection. A password alone binds nothing, so Mallory, who
//! phished Ann's password, gets nowhere from her own machine.
//!
//! In every other way a bind is a sign-in. The tenant admits it first, wrong
//! passwords count towards the lockout of the network they came from on the
//! account, and every refusal reads
//! the same, so a bind never tells an unknown address from a wrong
//! password, or which part of the proof was missing.
//!
//! A bind has no second step a sign-in could ask for. So while failures
//! from many networks put the account under attack, a bind from a network
//! that failed on it is refused, right password or not, and binds from
//! networks that never failed go on as before.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::authentication::events::login::LoginFailureReason;
use ianua_domain::domains::authentication::ldap_certificate::{
    DirectoryBind, LdapClientCertificate,
};
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::operations::directory_attempt::DirectoryBindAttempt;
use ianua_domain::domains::authentication::risk_engine::attack::AccountAttack;
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::rate_limit::{
    LoginAttemptTracker, RateLimitPolicy,
};
use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::PasswordCheck;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ActorRef, CertificateFingerprint, Email, Fact, IpAddress, OrganizationId, PasswordHash,
};
use time::OffsetDateTime;

use crate::acting::directory::DirectoryAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::{CallerContext, CallerIdentity, Credential, DirectoryBound};
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{CountedAccount, CredentialStore};
use crate::ports::directory::{BindThrottle, LdapCertificateStore};
use crate::ports::identity::UserStore;
use crate::ports::limits::PlanLimitsSource;
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authentication::sign_in_counts::{CountedAt, SignInCounts, lockout_of};
use crate::services::authentication::sign_in_gate;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::directory::admission::{
    ensure_within_bind_rate, invalid_credentials, named_tenant,
};
use crate::use_cases::directory::principal::{DirectoryBase, DirectoryPrincipal};

/// One bind attempt, as the LDAP adapter read it off the connection. It
/// holds the password, so it has no `Debug`.
pub struct BindRequest {
    /// The organization and tenant the bind DN names.
    pub base: DirectoryBase,
    /// The address the bind DN names.
    pub email: Email,
    /// The password presented with the bind.
    pub password: Secret,
    /// The fingerprint of the client certificate the connection presented
    /// in its TLS handshake, or `None` when it presented none.
    pub presented: Option<CertificateFingerprint>,
    /// The client's address, or that it could not be told.
    pub ip_address: Fact<IpAddress>,
}

/// The ports [`BindUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BindPorts {
    /// Finds the organization the DN names.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Finds the tenant the DN names, which admits the bind and sets its
    /// lockout.
    pub tenants: Arc<dyn TenantStore>,
    /// Holds each tenant's binds to a rate.
    pub throttle: Arc<dyn BindThrottle>,
    /// Finds the certificate the connection presented.
    pub certificates: Arc<dyn LdapCertificateStore>,
    /// Finds the account the DN names.
    pub users: Arc<dyn UserStore>,
    /// Reads the account's password hash.
    pub credentials: Arc<dyn CredentialStore>,
    /// The failed passwords counted per account and network, and the wait
    /// an account being guessed at asks, as sign-in keeps them.
    pub attempts: SignInCounts,
    /// Checks the presented password against the stored hash, under the
    /// node's cap on hashes running at once.
    pub hashing: PasswordHashing,
    /// What the bound person holds in their tenant.
    pub directory_authorities: Arc<dyn DirectoryAuthorities>,
    /// Reads the plan the bound person's later writes are held to.
    pub plan_limits: Arc<dyn PlanLimitsSource>,
}

/// Binds directory connections as the people they prove to be.
pub struct BindUseCase {
    ports: BindPorts,
}

/// One admitted attempt as the steps below read it.
struct Attempt<'a> {
    organization: OrganizationId,
    tenant: &'a ScopedTenant,
    request: &'a BindRequest,
    rate: RateLimitPolicy,
}

/// An account the domain bound, with its proof.
struct Bound {
    account: User<ResolvedTenant>,
    bind: DirectoryBind<ResolvedTenant>,
}

/// What checking an attempt came to: a bound account, or why not.
type Checked = Result<Bound, LoginFailureReason>;

/// What a bind records: its trail of events, and the attack on the account
/// it found, whose mark is kept once the trail is written.
struct Trail {
    attempt: DirectoryBindAttempt<ResolvedTenant>,
    attack: AccountAttack,
}

/// What a bind is proved against: the account with its stored password, and
/// the tenant's certificate with the fingerprint the connection presented.
struct Evidence<'a> {
    account: &'a User<ResolvedTenant>,
    stored: &'a PasswordHash,
    certificate: &'a LdapClientCertificate<ResolvedTenant>,
    presented: &'a CertificateFingerprint,
}

impl<'a> Evidence<'a> {
    /// `account` with its `stored` password, and `certificate` with the
    /// fingerprint `presented` on the connection.
    fn of(
        account: &'a User<ResolvedTenant>,
        stored: &'a PasswordHash,
        certificate: &'a LdapClientCertificate<ResolvedTenant>,
        presented: &'a CertificateFingerprint,
    ) -> Self {
        Self {
            account,
            stored,
            certificate,
            presented,
        }
    }
}

impl Trail {
    /// A trail begun for `request`, the account quiet until a check says
    /// it is under attack.
    fn opened(request: &BindRequest) -> Self {
        Self {
            attempt: DirectoryBindAttempt::new(&request.email, request.ip_address.clone()),
            attack: AccountAttack::Quiet,
        }
    }
}

impl BindUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: BindPorts) -> Self {
        Self { ports }
    }

    /// Checks the attempt once the account's pace has been waited out, and
    /// counts what it did against the network it came from. An attack the
    /// check found begun is raised on `trail`.
    async fn settled(&self, attempt: &Attempt<'_>, trail: &mut Trail) -> Result<Checked, AppError> {
        let at = counted_at(attempt);
        let attempts = &self.ports.attempts;
        let mut tracker = attempts.held(at, async { Familiarity::New }).await?;
        let checked = self.checked(attempt, &mut tracker, trail).await;
        attempts.settled(at, &tracker).await?;
        checked
    }

    /// The account the attempt binds, or why it is refused.
    ///
    /// The certificate is looked for first: a connection presenting none the
    /// tenant issued learns nothing about the address or the password, and
    /// counts nothing. While the account is under attack, a bind from a
    /// network that failed on it is refused after a password check's worth
    /// of hashing, and counts nothing either.
    async fn checked(
        &self,
        attempt: &Attempt<'_>,
        tracker: &mut LoginAttemptTracker,
        trail: &mut Trail,
    ) -> Result<Checked, AppError> {
        let Some((presented, certificate)) = self.presented_certificate(attempt).await? else {
            return Ok(Err(LoginFailureReason::MfaRequired));
        };
        let now = clock::now();
        if tracker.is_locked(now) {
            return Ok(Err(LoginFailureReason::AccountLocked));
        }
        let Some((account, stored)) = self.account(attempt).await? else {
            return self.unknown_account(attempt, tracker).await.map(Err);
        };
        if !self.attack_admits(attempt, &account, trail).await? {
            self.spend_a_password_check(attempt).await?;
            return Ok(Err(LoginFailureReason::RiskTooHigh));
        }
        let evidence = Evidence::of(&account, &stored, &certificate, &presented);
        let proved = self.proved(attempt, tracker, evidence).await?;
        match proved {
            Ok(bind) => Ok(Ok(Bound { account, bind })),
            Err(DomainError::Forbidden(_)) => self
                .refused(attempt, &certificate, &account, now)
                .await
                .map(Err),
            Err(other) => Err(AppError::from_domain(other)),
        }
    }

    /// Whether a bind of `account` from where `attempt` came may go on to
    /// its password, as an attack on the account allows: always while it is
    /// quiet, and under attack only from a network that has not failed on
    /// it. An attack this bind found begun is raised on `trail`.
    ///
    /// A bind has no second step to ask for, so a network that failed is
    /// turned away whatever it brings, while the owner's office, which did
    /// not fail, still binds.
    async fn attack_admits(
        &self,
        attempt: &Attempt<'_>,
        account: &User<ResolvedTenant>,
        trail: &mut Trail,
    ) -> Result<bool, AppError> {
        let at = counted_at(attempt);
        let attempts = &self.ports.attempts;
        let attack = attempts.attack(at).await?;
        if let Some(begun) = attack.begun() {
            trail.attempt.record_attack(account, begun);
        }
        trail.attack = attack;
        if !attack.is_under_attack() {
            return Ok(true);
        }
        let origin = attempts.origin_record(at).await?;
        Ok(attack.admits_bind(origin))
    }

    /// Whether the account's password and the certificate the connection
    /// presented prove the bind, the hash running under a permit.
    async fn proved(
        &self,
        attempt: &Attempt<'_>,
        tracker: &mut LoginAttemptTracker,
        evidence: Evidence<'_>,
    ) -> Result<Result<DirectoryBind<ResolvedTenant>, DomainError>, AppError> {
        let hasher = self.ports.hashing.permitted().await?;
        let check = PasswordCheck {
            raw: attempt.request.password.expose(),
            stored: evidence.stored,
            hasher: &hasher,
            tracker,
        };
        Ok(DirectoryBind::with_certificate(
            evidence.account,
            check,
            evidence.certificate,
            evidence.presented,
        ))
    }

    /// The fingerprint the connection presented and the tenant's
    /// certificate with it, when it presented one the tenant issued.
    async fn presented_certificate(
        &self,
        attempt: &Attempt<'_>,
    ) -> Result<
        Option<(
            CertificateFingerprint,
            LdapClientCertificate<ResolvedTenant>,
        )>,
        AppError,
    > {
        let Some(presented) = attempt.request.presented else {
            return Ok(None);
        };
        let found = self
            .ports
            .certificates
            .find_by_fingerprint(attempt.tenant, &presented)
            .await
            .or_internal()?;
        Ok(found.map(|certificate| (presented, certificate)))
    }

    /// The account the DN names and its password hash, when it has both.
    async fn account(
        &self,
        attempt: &Attempt<'_>,
    ) -> Result<Option<(User<ResolvedTenant>, PasswordHash)>, AppError> {
        let found = self
            .ports
            .users
            .find_by_email(attempt.tenant, &attempt.request.email)
            .await
            .or_internal()?;
        let Some(account) = found else {
            return Ok(None);
        };
        let stored = self
            .ports
            .credentials
            .find_password_hash(attempt.tenant, account.id())
            .await
            .or_internal()?;
        Ok(stored.map(|hash| (account, hash)))
    }

    /// The refusal for an address with no account or no password, reached
    /// only after as long as a real password check takes, and counted under
    /// the lockout of where it came from like a wrong password.
    async fn unknown_account(
        &self,
        attempt: &Attempt<'_>,
        tracker: &mut LoginAttemptTracker,
    ) -> Result<LoginFailureReason, AppError> {
        self.spend_a_password_check(attempt).await?;
        tracker.record_failure();
        Ok(LoginFailureReason::UserNotFound)
    }

    /// Why the domain refused the bind of `account` over `certificate`.
    ///
    /// A certificate that does not let the account in is refused before
    /// the password is looked at. The password is hashed all the same then,
    /// so that refusal takes as long as a wrong password and the time does
    /// not tell which was wrong.
    async fn refused(
        &self,
        attempt: &Attempt<'_>,
        certificate: &LdapClientCertificate<ResolvedTenant>,
        account: &User<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<LoginFailureReason, AppError> {
        match refusal_reason(certificate, account, now) {
            LoginFailureReason::MfaFailed => {
                self.spend_a_password_check(attempt).await?;
                Ok(LoginFailureReason::MfaFailed)
            }
            reason => Ok(reason),
        }
    }

    /// Hashes the presented password and drops it, taking as long as
    /// checking it would, under a permit like a real check.
    async fn spend_a_password_check(&self, attempt: &Attempt<'_>) -> Result<(), AppError> {
        let hasher = self.ports.hashing.permitted().await?;
        let _ = hasher.hash(attempt.request.password.expose());
        Ok(())
    }

    /// The bind `attempt` proves, or its refusal, raised on `trail` and
    /// recorded through `auditor` as done by the platform.
    async fn bound(
        &self,
        attempt: &Attempt<'_>,
        trail: &mut Trail,
        auditor: &RequestAuditor,
    ) -> Result<Bound, AppError> {
        let reason = match self.settled(attempt, trail).await? {
            Ok(bound) => return Ok(bound),
            Err(reason) => reason,
        };
        trail.attempt.record_refusal(reason);
        auditor
            .dispatch_by(&ActorRef::System, trail.attempt.take_events(attempt.tenant))
            .await
            .or_internal()?;
        self.attack_recorded(attempt, trail).await?;
        Err(invalid_credentials())
    }

    /// Marks the account `attempt` named under the attack `trail` found
    /// begun, now that the trail is written.
    async fn attack_recorded(&self, attempt: &Attempt<'_>, trail: &Trail) -> Result<(), AppError> {
        self.ports
            .attempts
            .mark_recorded(counted_at(attempt), trail.attack)
            .await
    }

    /// The person `bound` is, with what they hold in the tenant now, and
    /// the caller their writes come as.
    async fn principal(
        &self,
        attempt: &Attempt<'_>,
        bound: Bound,
    ) -> Result<DirectoryPrincipal, AppError> {
        let authority = self
            .ports
            .directory_authorities
            .authority(attempt.tenant, &bound.account, &bound.bind)
            .await?;
        let Bound { account, bind } = bound;
        let credential = Credential::DirectoryBind(DirectoryBound::new(bind));
        let caller = self.bound_caller(attempt, &account, credential).await?;
        Ok(DirectoryPrincipal::bound(
            authority,
            caller,
            attempt.request.base.clone(),
            &account,
        ))
    }

    /// `account` as a caller of its tenant, coming with `credential`, under
    /// the organization's plan.
    async fn bound_caller(
        &self,
        attempt: &Attempt<'_>,
        account: &User<ResolvedTenant>,
        credential: Credential,
    ) -> Result<CallerContext, AppError> {
        let plan = self
            .ports
            .plan_limits
            .for_tenant(attempt.tenant)
            .await
            .or_internal()?;
        let caller = CallerContext::new(
            CallerIdentity::TenantUser(*account.id()),
            credential,
            attempt.organization,
            **attempt.tenant,
            plan,
        )?;
        let client_ip = attempt.request.ip_address.known().cloned();
        Ok(caller.with_request_metadata(client_ip, None))
    }
}

impl Command for BindUseCase {
    type Caller = ();
    type Input = BindRequest;
    type Output = Result<DirectoryPrincipal, AppError>;

    /// Binds the connection as the account `request` names, when its
    /// password and the certificate the connection presented prove it.
    ///
    /// A refused bind in a known tenant records `authentication.login_failed`
    /// with its reason; a bind that succeeds records
    /// `authentication.directory_bind_succeeded`. A bind that finds the
    /// account's attack begun records `authentication.account_under_attack`
    /// with it.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` hides unknown organization/tenant/address, wrong passwords, network lockout, failures on an attacked account, unusable/foreign/missing certificates, and accounts unable to sign in.
    /// - `AppError::TooManyRequests` for excessive binds; `TenantUnavailable` for a closed tenant.
    /// - `AppError::Forbidden` for disabled passwords or a refused origin; `Busy` when hashing cannot start, without counting a failure.
    /// - `AppError::Internal` on storage, hashing, throttle or audit failure, or invalid lockout settings.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: BindRequest,
    ) -> Result<DirectoryPrincipal, AppError> {
        let tenants = self.ports.tenants.as_ref();
        let organizations = self.ports.organizations.as_ref();
        let (organization, tenant) = named_tenant(organizations, tenants, &request.base).await?;
        ensure_within_bind_rate(self.ports.throttle.as_ref(), &tenant).await?;
        let client_ip = request.ip_address.as_ref();
        let (record, _) =
            sign_in_gate::admit(tenants, &tenant, AuthMethod::Password, client_ip).await?;
        let auditor = auditor.with_organization(organization).with_tenant(*tenant);
        let attempt = Attempt {
            organization,
            tenant: &tenant,
            request: &request,
            rate: lockout_of(record.auth_config().limits())?,
        };
        let mut trail = Trail::opened(&request);
        let bound = self.bound(&attempt, &mut trail, &auditor).await?;
        trail.attempt.record_user_bind(&bound.account);
        let principal = self.principal(&attempt, bound).await?;
        auditor
            .dispatch_by(
                &principal.authority().actor(),
                trail.attempt.take_events(&tenant),
            )
            .await
            .or_internal()?;
        self.attack_recorded(&attempt, &trail).await?;
        Ok(principal)
    }
}

/// Where `attempt`'s password is counted: the address it names in its
/// tenant, from the network it came from, under the tenant's lockout.
fn counted_at<'a>(attempt: &'a Attempt<'_>) -> CountedAt<'a> {
    CountedAt {
        account: CountedAccount::Tenant {
            tenant: attempt.tenant,
            email: &attempt.request.email,
        },
        origin: AttemptOrigin::of(attempt.request.ip_address.as_ref()),
        policy: &attempt.rate,
    }
}

/// Why the domain refused a bind, for the record: the certificate does not
/// allow the account a bind now (it is revoked, expired or another
/// account's, or the account is shut), or the password is wrong.
fn refusal_reason(
    certificate: &LdapClientCertificate<ResolvedTenant>,
    account: &User<ResolvedTenant>,
    now: OffsetDateTime,
) -> LoginFailureReason {
    if certificate.admits_write(account, now) {
        return LoginFailureReason::BadPassword;
    }
    LoginFailureReason::MfaFailed
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::{PrincipalRef, TenantId, TenantSlug, UserId};

    use super::*;
    use crate::acting::directory::DirectoryActing;
    use crate::ports::authentication::PasswordHashPermits;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::authentication::{
        AllowingThrottle, BusyHashPermits, CertificateStanding, CountingHasher, FakeHashPermits,
        FakeLdapCertificateStore, FakeSignInAttemptCounts, ldap_certificate,
    };
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_role,
    };
    use crate::test_support::identity::{FakeUserStore, RecordingCredentialStore, stored_user};
    use crate::test_support::organization::{org_store_with, test_org};
    use crate::test_support::tenant::tenant_store_in_status;
    use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const ANN: &str = "ann@acme.test";
    const PASSWORD: &str = "right password";

    /// The fingerprint of the certificate Ann's laptop holds.
    fn laptop() -> CertificateFingerprint {
        CertificateFingerprint::from_digest([7; 32])
    }

    /// The fingerprint of a certificate the tenant never issued.
    fn strange_machine() -> CertificateFingerprint {
        CertificateFingerprint::from_digest([8; 32])
    }

    /// A throttle that answers every bind with `error`.
    struct RefusingThrottle(fn() -> DomainError);

    #[async_trait]
    impl BindThrottle for RefusingThrottle {
        async fn check_and_record(&self, _tenant_id: &TenantId) -> Result<(), DomainError> {
            Err((self.0)())
        }
    }

    /// The tenant `acme` of `acme-corp`, where Ann's account has the
    /// password [`PASSWORD`] and her laptop a certificate.
    struct Directory {
        ann: UserId,
        users: Arc<FakeUserStore>,
        certificates: Arc<FakeLdapCertificateStore>,
        access: Arc<FakeAccessRecordStore>,
        tenant_status: TenantStatus,
        throttle: Arc<dyn BindThrottle>,
        attempts: Arc<FakeSignInAttemptCounts>,
        hasher: Arc<CountingHasher>,
        permits: Arc<dyn PasswordHashPermits>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Directory {
        /// Ann's laptop holds a certificate standing as `standing` says.
        fn with_certificate(standing: CertificateStanding) -> Self {
            let ann = UserId::new();
            let certificate = ldap_certificate(ann, laptop(), standing);
            Self::holding(
                ann,
                FakeLdapCertificateStore::holding(tenant(), [certificate]),
            )
        }

        /// Ann's laptop holds a certificate in force.
        fn anns() -> Self {
            Self::with_certificate(CertificateStanding::InForce)
        }

        fn holding(ann: UserId, certificates: FakeLdapCertificateStore) -> Self {
            Self {
                ann,
                users: Arc::new(FakeUserStore::with_user(ann, ANN)),
                certificates: Arc::new(certificates),
                access: Arc::new(FakeAccessRecordStore::empty()),
                tenant_status: TenantStatus::Active,
                throttle: Arc::new(AllowingThrottle),
                attempts: Arc::new(FakeSignInAttemptCounts::default()),
                hasher: Arc::new(CountingHasher::default()),
                permits: Arc::new(FakeHashPermits::default()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// Failures against Ann's account from twenty networks, twice the
        /// tenant's limit of ten a network, `192.0.2.0` to `192.0.2.19`
        /// among them: her account is under attack.
        fn under_attack(self) -> Self {
            let tenant = test_ctx().tenant();
            let ann = Email::new(ANN).unwrap();
            let account = CountedAccount::Tenant {
                tenant: &tenant,
                email: &ann,
            };
            let attempts = Arc::new(FakeSignInAttemptCounts::guessed_from_networks(account, 20));
            Self { attempts, ..self }
        }

        fn bind(&self, request: BindRequest) -> Result<DirectoryPrincipal, AppError> {
            let use_case = BindUseCase::new(BindPorts {
                organizations: org_store_with([test_org(
                    test_ctx().organization_id(),
                    "acme-corp",
                )]),
                tenants: tenant_store_in_status(self.tenant_status),
                throttle: self.throttle.clone(),
                certificates: self.certificates.clone(),
                users: self.users.clone(),
                credentials: Arc::new(RecordingCredentialStore::holding(
                    self.ann,
                    &FakeHasher.hash(PASSWORD).unwrap(),
                )),
                attempts: SignInCounts::new(self.attempts.clone(), Fake::fake()),
                hashing: PasswordHashing::new(self.hasher.clone(), self.permits.clone()),
                directory_authorities: Arc::new(DirectoryActing::new(self.access.clone())),
                ..BindPorts::fakes()
            });
            block_on(use_case.execute(&(), &test_auditor(self.audit.clone()), request))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        /// The reason the last refusal was recorded with.
        fn recorded_reason(&self) -> String {
            let payloads = self.audit.all_payloads();
            let last = payloads.last().unwrap();
            last.get("reason").unwrap().to_owned()
        }
    }

    fn tenant() -> TenantId {
        test_ctx().tenant_id()
    }

    fn slug(value: &str) -> TenantSlug {
        TenantSlug::new(value, &crate::test_support::tenant::cfg().slug).unwrap()
    }

    fn acme() -> DirectoryBase {
        DirectoryBase {
            organization: slug("acme-corp"),
            tenant: slug("acme"),
        }
    }

    fn bind_as(
        email: &str,
        password: &str,
        presented: Option<CertificateFingerprint>,
    ) -> BindRequest {
        BindRequest {
            base: acme(),
            email: Email::new(email).unwrap(),
            password: Secret::new(password),
            presented,
            ip_address: Fact::Unknown,
        }
    }

    /// Ann binding from her laptop with `password`.
    fn ann_binds(password: &str) -> BindRequest {
        bind_as(ANN, password, Some(laptop()))
    }

    /// `request`, its connection coming from `ip`.
    fn from(ip: &str, request: BindRequest) -> BindRequest {
        BindRequest {
            ip_address: Fact::Known(IpAddress::new(ip).unwrap()),
            ..request
        }
    }

    fn refused(result: &Result<DirectoryPrincipal, AppError>) -> bool {
        matches!(result, Err(AppError::NotFound(message)) if message == "invalid credentials")
    }

    /// Under account attack, a network with failed attempts cannot bind
    /// even with the correct password and certificate. The refusal records
    /// high risk and the detected attack.
    #[test]
    fn under_attack_a_network_that_failed_binds_nothing() {
        let directory = Directory::anns().under_attack();

        let result = directory.bind(from("192.0.2.3", ann_binds(PASSWORD)));

        assert!(refused(&result));
        assert_eq!(directory.recorded_reason(), "risk_too_high");
        assert!(
            directory
                .recorded()
                .contains(&"authentication.account_under_attack".to_owned())
        );
    }

    /// Ann's directory client binds from the office, a network that never
    /// failed on her account, while it is under attack. It binds as ever.
    #[test]
    fn under_attack_a_network_that_never_failed_still_binds() {
        let directory = Directory::anns().under_attack();

        let principal = directory
            .bind(from("203.0.113.7", ann_binds(PASSWORD)))
            .unwrap();

        assert_eq!(principal.user_id(), &directory.ann);
    }

    /// Ann's directory client binds from her laptop with her password. The
    /// connection is bound as Ann in her tenant, and the bind is recorded.
    #[test]
    fn a_password_over_the_accounts_certificate_binds_the_account() {
        let directory = Directory::anns();

        let principal = directory.bind(ann_binds(PASSWORD)).unwrap();

        assert_eq!(principal.user_id(), &directory.ann);
        assert_eq!(principal.tenant(), &ScopedTenant::for_test(tenant()));
        assert_eq!(principal.user_label().as_str(), ANN);
        assert_eq!(
            directory.recorded(),
            ["authentication.directory_bind_succeeded"]
        );
    }

    /// Ann's role lets her view users. The bound connection holds that, and
    /// nothing she was not given.
    #[test]
    fn the_bound_person_holds_what_the_tenant_grants_them() {
        let directory = Directory::anns();
        let reader = stored_role(
            "reader",
            vec![SystemPermission::Users(UserAction::View)],
            vec![],
        );
        let assignment = stored_assignment(PrincipalRef::User(directory.ann), *reader.id());
        directory.access.replace(
            tenant(),
            AccessRecords {
                roles: vec![reader],
                assignments: vec![assignment],
                ..AccessRecords::default()
            },
        );

        let principal = directory.bind(ann_binds(PASSWORD)).unwrap();

        assert!(
            principal
                .authority()
                .holds(SystemPermission::Users(UserAction::View))
        );
        assert!(
            !principal
                .authority()
                .holds(SystemPermission::Users(UserAction::Delete))
        );
    }

    /// A wrong password with Ann's certificate returns invalid credentials
    /// and records a login failure for a bad password.
    #[test]
    fn a_wrong_password_is_refused_and_recorded() {
        let directory = Directory::anns();

        let result = directory.bind(ann_binds("guess"));

        assert!(refused(&result));
        assert_eq!(directory.recorded(), ["authentication.login_failed"]);
        assert_eq!(directory.recorded_reason(), "bad_password");
    }

    /// Exhausted hash permits return a busy response without hashing the
    /// password or counting a failure against Ann's account.
    #[test]
    fn a_busy_node_binds_nothing_and_hashes_nothing() {
        let directory = Directory {
            permits: Arc::new(BusyHashPermits),
            ..Directory::anns()
        };

        let result = directory.bind(ann_binds(PASSWORD));

        assert!(matches!(result, Err(AppError::Busy)));
        assert_eq!(directory.hasher.hashed(), 0);
        let acme = ScopedTenant::for_test(tenant());
        let ann = Email::new(ANN).unwrap();
        let counted = directory.attempts.on_account(CountedAccount::Tenant {
            tenant: &acme,
            email: &ann,
        });
        assert_eq!(counted, 0);
    }

    /// An unknown address receives the same invalid-credentials response
    /// as a wrong password, while the audit records the missing user.
    #[test]
    fn an_unknown_address_answers_like_a_wrong_password() {
        let directory = Directory::anns();

        let result = directory.bind(bind_as("nobody@acme.test", PASSWORD, Some(laptop())));

        assert!(refused(&result));
        assert_eq!(directory.recorded_reason(), "user_not_found");
    }

    /// Repeated guesses lock out their source network even with the right
    /// password; the refusal records the lock while Ann's office can bind.
    #[test]
    fn a_locked_out_network_is_refused_even_the_right_password() {
        let directory = Directory::anns();
        for _ in 0..20 {
            let _ = directory.bind(from("198.51.100.66", ann_binds("guess")));
        }

        let mallory = directory.bind(from("198.51.100.66", ann_binds(PASSWORD)));
        let reason = directory.recorded_reason();
        let ann = directory.bind(from("203.0.113.7", ann_binds(PASSWORD)));

        assert!(refused(&mallory));
        assert_eq!(reason, "account_locked");
        assert!(ann.is_ok());
    }

    /// A correct password without a client certificate cannot bind Ann's
    /// account and records the missing second factor.
    #[test]
    fn a_password_without_a_certificate_binds_nothing() {
        let directory = Directory::anns();

        let result = directory.bind(bind_as(ANN, PASSWORD, None));

        assert!(refused(&result));
        assert_eq!(directory.recorded_reason(), "mfa_required");
    }

    /// Mallory guesses Ann's password many times from a machine with no
    /// certificate. None of it counts, so Ann still binds from her laptop.
    #[test]
    fn guesses_without_a_certificate_do_not_lock_the_address() {
        let directory = Directory::anns();
        for _ in 0..20 {
            let _ = directory.bind(bind_as(ANN, "guess", None));
        }

        let result = directory.bind(ann_binds(PASSWORD));

        assert!(result.is_ok());
    }

    /// A certificate fingerprint absent from the tenant cannot establish
    /// a bind, even with Ann's correct password.
    #[test]
    fn a_certificate_the_tenant_never_issued_binds_nothing() {
        let directory = Directory::anns();

        let result = directory.bind(bind_as(ANN, PASSWORD, Some(strange_machine())));

        assert!(refused(&result));
    }

    /// A revoked certificate prevents binding with Ann's correct password
    /// and records a failed second factor.
    #[test]
    fn a_revoked_certificate_binds_nothing() {
        let directory = Directory::with_certificate(CertificateStanding::Revoked);

        let result = directory.bind(ann_binds(PASSWORD));

        assert!(refused(&result));
        assert_eq!(directory.recorded_reason(), "mfa_failed");
    }

    /// How many passwords the bind hashed or checked when Ann's laptop,
    /// holding a certificate standing as `standing` says, binds as Ann with
    /// a wrong password.
    fn password_work_for(standing: CertificateStanding) -> usize {
        let directory = Directory::with_certificate(standing);
        let result = directory.bind(ann_binds("guess"));
        assert!(refused(&result));
        directory.hasher.hashed()
    }

    /// Rejecting a revoked certificate performs the same number of password
    /// operations as rejecting a wrong password with a valid certificate.
    #[test]
    fn a_refused_certificate_costs_as_much_as_a_wrong_password() {
        let wrong_password = password_work_for(CertificateStanding::InForce);

        let refused_certificate = password_work_for(CertificateStanding::Revoked);

        assert_eq!(refused_certificate, wrong_password);
    }

    /// An expired client certificate prevents a bind despite the correct
    /// account password.
    #[test]
    fn an_expired_certificate_binds_nothing() {
        let directory = Directory::with_certificate(CertificateStanding::Expired);

        let result = directory.bind(ann_binds(PASSWORD));

        assert!(refused(&result));
    }

    /// A certificate issued to another account cannot be paired with
    /// Ann's password to bind as Ann.
    #[test]
    fn another_accounts_certificate_binds_nothing() {
        let mallorys = ldap_certificate(
            UserId::new(),
            strange_machine(),
            CertificateStanding::InForce,
        );
        let directory = Directory::holding(
            UserId::new(),
            FakeLdapCertificateStore::holding(tenant(), [mallorys]),
        );

        let result = directory.bind(bind_as(ANN, PASSWORD, Some(strange_machine())));

        assert!(refused(&result));
    }

    /// Ann's certificate from another tenant cannot establish a bind in
    /// the requested tenant, even for the same account ID.
    #[test]
    fn a_certificate_from_another_tenant_binds_nothing() {
        let ann = UserId::new();
        let elsewhere = ldap_certificate(ann, laptop(), CertificateStanding::InForce);
        let directory = Directory::holding(
            ann,
            FakeLdapCertificateStore::holding(TenantId::new(), [elsewhere]),
        );

        let result = directory.bind(ann_binds(PASSWORD));

        assert!(refused(&result));
    }

    /// A locked account cannot bind with its correct password and a
    /// certificate still in force.
    #[test]
    fn a_locked_account_binds_nothing() {
        let directory = Directory {
            users: Arc::new(FakeUserStore::empty()),
            ..Directory::anns()
        };
        directory
            .users
            .add(stored_user(directory.ann, ANN, UserStatus::Locked));

        let result = directory.bind(ann_binds(PASSWORD));

        assert!(refused(&result));
    }

    /// A suspended tenant returns an unavailable error for Ann's bind
    /// without recording an authentication event.
    #[test]
    fn a_suspended_tenant_refuses_binds() {
        let directory = Directory {
            tenant_status: TenantStatus::Suspended,
            ..Directory::anns()
        };

        let result = directory.bind(ann_binds(PASSWORD));

        assert!(matches!(result, Err(AppError::TenantUnavailable(_))));
        assert!(directory.recorded().is_empty());
    }

    /// Naming a nonexistent tenant in the bind returns invalid credentials
    /// rather than revealing whether that tenant exists.
    #[test]
    fn an_unknown_tenant_answers_like_bad_credentials() {
        let directory = Directory::anns();
        let mut request = ann_binds(PASSWORD);
        request.base.tenant = slug("elsewhere");

        let result = directory.bind(request);

        assert!(refused(&result));
    }

    /// Naming a nonexistent organization in the bind returns the generic
    /// invalid-credentials response.
    #[test]
    fn an_unknown_organization_answers_like_bad_credentials() {
        let directory = Directory::anns();
        let mut request = ann_binds(PASSWORD);
        request.base.organization = slug("nobody-corp");

        let result = directory.bind(request);

        assert!(refused(&result));
    }

    /// A bind refused by the tenant throttle returns too many requests
    /// even when its credentials are correct.
    #[test]
    fn binds_past_the_tenants_rate_are_held_back() {
        let directory = Directory {
            throttle: Arc::new(RefusingThrottle(|| DomainError::forbidden("rate exceeded"))),
            ..Directory::anns()
        };

        let result = directory.bind(ann_binds(PASSWORD));

        assert!(matches!(result, Err(AppError::TooManyRequests(_))));
    }

    /// The throttle's store is down. The bind fails as a fault on our side,
    /// not as a rate refusal.
    #[test]
    fn a_throttle_that_cannot_be_asked_is_a_fault() {
        let directory = Directory {
            throttle: Arc::new(RefusingThrottle(|| DomainError::infra_msg("down"))),
            ..Directory::anns()
        };

        let result = directory.bind(ann_binds(PASSWORD));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
