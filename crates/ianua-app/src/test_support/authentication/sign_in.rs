//! Fakes for signing in: finding the account, throttling attempts, breach
//! checks, where a sign-in comes from and break glass.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
use ianua_domain::domains::authentication::operations::password_login::LoginCandidate;
use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::domains::authentication::risk_engine::attack::{
    AttackMark, AttackSigns, FailingNetworks,
};
use ianua_domain::domains::authentication::risk_engine::history::SignInHistory;
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::pressure::FailureCount;
use ianua_domain::domains::authentication::risk_engine::rate_limit::Lockout;
use ianua_domain::domains::authorization::break_glass::{
    BreakGlassGrant, BreakGlassGrantRow, BreakGlassPolicy, BreakGlassPolicyRow,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    BreakGlassGrantId, Email, Fact, IpAddress, Lifetime, Revocation, TenantId, UserId,
};
use time::{Duration, OffsetDateTime};

use crate::ports::TenantScoped;
use crate::ports::authentication::{
    AttackClaim, BreakGlassStore, CountedAccount, CredentialBreachChecker, Geolocator,
    SignInAttemptCounts, SignInHistoryStore, UserLookup,
};
use crate::ports::directory::BindThrottle;
use crate::ports::runtime::Pause;
use crate::tenancy::ScopedTenant;
use crate::test_support::{Fake, test_ctx};

/// In-memory user lookup, finding each account by email within its tenant.
#[derive(Default)]
pub struct FakeUserLookup {
    users: Vec<(TenantId, Email, LoginCandidate)>,
}

impl TenantScoped for FakeUserLookup {}

impl FakeUserLookup {
    /// Nobody has an account.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Each `(email, candidate)` has an account in the test tenant.
    #[must_use]
    pub fn holding(users: impl IntoIterator<Item = (Email, LoginCandidate)>) -> Self {
        let tenant_id = test_ctx().tenant_id();
        Self {
            users: users
                .into_iter()
                .map(|(email, candidate)| (tenant_id, email, candidate))
                .collect(),
        }
    }
}

#[async_trait]
impl UserLookup for FakeUserLookup {
    async fn find_by_email(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<LoginCandidate>, DomainError> {
        Ok(self
            .users
            .iter()
            .find(|(held_in, held, _)| held_in == &**tenant_id && held == email)
            .map(|(_, _, candidate)| copy_candidate(candidate)))
    }
}

/// A copy of `candidate`, which does not implement `Clone`.
fn copy_candidate(candidate: &LoginCandidate) -> LoginCandidate {
    LoginCandidate {
        user_id: candidate.user_id,
        password_hash: candidate.password_hash.clone(),
        status: candidate.status,
        email_standing: candidate.email_standing,
        enrolment: candidate.enrolment,
        vouching: candidate.vouching,
        password_due: candidate.password_due,
    }
}

/// The key an account's failures are counted under, as the real counts
/// key them: the tenant or organization, or the operator plane, and the
/// address.
fn counted_key(account: CountedAccount<'_>) -> String {
    match account {
        CountedAccount::Tenant { tenant, email } => format!("tenant:{}:{email}", **tenant),
        CountedAccount::Organization {
            organization,
            email,
        } => format!("organization:{organization}:{email}"),
        CountedAccount::Operator { email } => format!("operator:{email}"),
    }
}

/// What [`FakeSignInAttemptCounts`] holds.
#[derive(Default)]
struct HeldCounts {
    from_origins: HashMap<(String, AttemptOrigin), u32>,
    on_accounts: HashMap<String, u64>,
    lockouts: HashMap<(String, AttemptOrigin), OffsetDateTime>,
    failing_origins: HashMap<String, HashSet<AttemptOrigin>>,
    attack_claims: HashMap<String, OffsetDateTime>,
    attack_marks: HashMap<String, OffsetDateTime>,
}

impl HeldCounts {
    /// Counts one failure from `origin` against the account keyed `account`,
    /// and answers the origin's count.
    fn failed(&mut self, account: String, origin: AttemptOrigin) -> u32 {
        *self.on_accounts.entry(account.clone()).or_default() += 1;
        self.failing_origins
            .entry(account.clone())
            .or_default()
            .insert(origin);
        let from_origin = self.from_origins.entry((account, origin)).or_default();
        *from_origin += 1;
        *from_origin
    }
}

/// In-memory counts of failed passwords per account and origin, and per
/// account, with each origin's lockout, the origins that failed on each
/// account and each account's attack claim and mark, keyed as the real
/// counts key them. Each step takes one lock, so two guesses at once both
/// count. Nothing lapses but a lockout, a claim or a mark, at its end.
#[derive(Default)]
pub struct FakeSignInAttemptCounts {
    held: Mutex<HeldCounts>,
}

impl FakeSignInAttemptCounts {
    /// Counts with one failure against `account` from each of `networks`
    /// networks, as a botnet spread over them leaves it.
    #[must_use]
    pub fn guessed_from_networks(account: CountedAccount<'_>, networks: u8) -> Self {
        let counts = Self::default();
        {
            let mut held = counts.held.lock().unwrap();
            for network in 0..networks {
                let ip = IpAddress::new(format!("192.0.2.{network}")).unwrap();
                held.failed(counted_key(account), AttemptOrigin::of(Fact::Known(&ip)));
            }
        }
        counts
    }

    /// Whether `account` is marked under attack now.
    #[must_use]
    pub fn marked_under_attack(&self, account: CountedAccount<'_>) -> bool {
        self.held
            .lock()
            .unwrap()
            .attack_marks
            .get(&counted_key(account))
            .is_some_and(|until| *until > clock::now())
    }

    /// Counts with `failures` already counted against `account` from other
    /// networks, as a botnet spread over many leaves it.
    #[must_use]
    pub fn guessed_at(account: CountedAccount<'_>, failures: u64) -> Self {
        let counts = Self::default();
        counts
            .held
            .lock()
            .unwrap()
            .on_accounts
            .insert(counted_key(account), failures);
        counts
    }

    /// The failures counted from `origin` against `account`.
    #[must_use]
    pub fn from_origin(&self, account: CountedAccount<'_>, origin: &AttemptOrigin) -> u32 {
        let key = (counted_key(account), *origin);
        self.held
            .lock()
            .unwrap()
            .from_origins
            .get(&key)
            .copied()
            .unwrap_or_default()
    }

    /// The failures counted against `account` from every origin.
    #[must_use]
    pub fn on_account(&self, account: CountedAccount<'_>) -> u64 {
        self.held
            .lock()
            .unwrap()
            .on_accounts
            .get(&counted_key(account))
            .copied()
            .unwrap_or_default()
    }
}

#[async_trait]
impl SignInAttemptCounts for FakeSignInAttemptCounts {
    async fn lockout(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
    ) -> Result<Lockout, DomainError> {
        let key = (counted_key(account), *origin);
        let held = self.held.lock().unwrap();
        Ok(held
            .lockouts
            .get(&key)
            .filter(|until| **until > clock::now())
            .map_or(Lockout::Open, |until| Lockout::Until(*until)))
    }

    async fn account_failures(
        &self,
        account: CountedAccount<'_>,
    ) -> Result<FailureCount, DomainError> {
        Ok(FailureCount::from(self.on_account(account)))
    }

    async fn origin_failures(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
    ) -> Result<u32, DomainError> {
        Ok(self.from_origin(account, origin))
    }

    async fn attack_signs(&self, account: CountedAccount<'_>) -> Result<AttackSigns, DomainError> {
        let key = counted_key(account);
        let held = self.held.lock().unwrap();
        let networks = held.failing_origins.get(&key).map_or(0, HashSet::len);
        let mark = match held.attack_marks.get(&key) {
            Some(until) if *until > clock::now() => AttackMark::Marked,
            Some(_) | None => AttackMark::Unmarked,
        };
        Ok(AttackSigns::new(
            FailingNetworks::from(u64::try_from(networks).unwrap()),
            mark,
        ))
    }

    async fn claim_attack(
        &self,
        account: CountedAccount<'_>,
        claim: Lifetime,
    ) -> Result<AttackClaim, DomainError> {
        let key = counted_key(account);
        let mut held = self.held.lock().unwrap();
        let now = clock::now();
        if held
            .attack_claims
            .get(&key)
            .is_some_and(|until| *until > now)
        {
            return Ok(AttackClaim::ClaimedBefore);
        }
        held.attack_claims.insert(key, claim.ends_after(now));
        Ok(AttackClaim::ClaimedNow)
    }

    async fn mark_attack(
        &self,
        account: CountedAccount<'_>,
        lasting: Lifetime,
    ) -> Result<(), DomainError> {
        let key = counted_key(account);
        let mut held = self.held.lock().unwrap();
        held.attack_marks
            .insert(key, lasting.ends_after(clock::now()));
        Ok(())
    }

    async fn count_failure(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
        _window: Lifetime,
    ) -> Result<u32, DomainError> {
        let account = counted_key(account);
        Ok(self.held.lock().unwrap().failed(account, *origin))
    }

    async fn lock(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
        until: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let key = (counted_key(account), *origin);
        let mut held = self.held.lock().unwrap();
        held.from_origins.remove(&key);
        held.lockouts.insert(key, until);
        Ok(())
    }

    async fn clear(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
    ) -> Result<(), DomainError> {
        let key = (counted_key(account), *origin);
        self.held.lock().unwrap().from_origins.remove(&key);
        Ok(())
    }
}

/// Counts that cannot be reached: every read and write fails.
pub struct UnreachableSignInAttemptCounts;

#[async_trait]
impl SignInAttemptCounts for UnreachableSignInAttemptCounts {
    async fn lockout(
        &self,
        _account: CountedAccount<'_>,
        _origin: &AttemptOrigin,
    ) -> Result<Lockout, DomainError> {
        Err(DomainError::infra_msg("the counts are unreachable"))
    }

    async fn account_failures(
        &self,
        _account: CountedAccount<'_>,
    ) -> Result<FailureCount, DomainError> {
        Err(DomainError::infra_msg("the counts are unreachable"))
    }

    async fn origin_failures(
        &self,
        _account: CountedAccount<'_>,
        _origin: &AttemptOrigin,
    ) -> Result<u32, DomainError> {
        Err(DomainError::infra_msg("the counts are unreachable"))
    }

    async fn attack_signs(&self, _account: CountedAccount<'_>) -> Result<AttackSigns, DomainError> {
        Err(DomainError::infra_msg("the counts are unreachable"))
    }

    async fn claim_attack(
        &self,
        _account: CountedAccount<'_>,
        _claim: Lifetime,
    ) -> Result<AttackClaim, DomainError> {
        Err(DomainError::infra_msg("the counts are unreachable"))
    }

    async fn mark_attack(
        &self,
        _account: CountedAccount<'_>,
        _lasting: Lifetime,
    ) -> Result<(), DomainError> {
        Err(DomainError::infra_msg("the counts are unreachable"))
    }

    async fn count_failure(
        &self,
        _account: CountedAccount<'_>,
        _origin: &AttemptOrigin,
        _window: Lifetime,
    ) -> Result<u32, DomainError> {
        Err(DomainError::infra_msg("the counts are unreachable"))
    }

    async fn lock(
        &self,
        _account: CountedAccount<'_>,
        _origin: &AttemptOrigin,
        _until: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Err(DomainError::infra_msg("the counts are unreachable"))
    }

    async fn clear(
        &self,
        _account: CountedAccount<'_>,
        _origin: &AttemptOrigin,
    ) -> Result<(), DomainError> {
        Err(DomainError::infra_msg("the counts are unreachable"))
    }
}

/// A pause that returns at once and remembers every wait it was asked for.
#[derive(Default)]
pub struct RecordingPause {
    waits: Mutex<Vec<Duration>>,
}

impl RecordingPause {
    /// Every wait asked for, in order.
    #[must_use]
    pub fn waited(&self) -> Vec<Duration> {
        self.waits.lock().unwrap().clone()
    }
}

#[async_trait]
impl Pause for RecordingPause {
    async fn hold(&self, wait: Duration) {
        self.waits.lock().unwrap().push(wait);
    }
}

/// Bind throttle that never holds anyone back.
pub struct AllowingThrottle;

#[async_trait]
impl BindThrottle for AllowingThrottle {
    async fn check_and_record(&self, _tenant_id: &TenantId) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Breach checker that answers every password with the same status, clean
/// unless set.
pub struct FakeBreachChecker {
    /// The status every check returns.
    pub status: BreachStatus,
}

impl Default for FakeBreachChecker {
    fn default() -> Self {
        Self {
            status: BreachStatus::Clean,
        }
    }
}

#[async_trait]
impl CredentialBreachChecker for FakeBreachChecker {
    async fn check(&self, _raw_password: &Secret) -> Result<BreachStatus, DomainError> {
        Ok(self.status)
    }
}

/// Breach checker whose service cannot be reached. It counts how often it
/// was asked, so a test can show a deployment that does not check never
/// asks.
#[derive(Default)]
pub struct UnreachableBreachChecker {
    asked: AtomicUsize,
}

impl UnreachableBreachChecker {
    /// How many passwords it was asked about.
    #[must_use]
    pub fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CredentialBreachChecker for UnreachableBreachChecker {
    async fn check(&self, _raw_password: &Secret) -> Result<BreachStatus, DomainError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Err(DomainError::infra_msg("breach service unreachable"))
    }
}

/// Geolocator whose database cannot be read.
pub struct UnreachableGeolocator;

#[async_trait]
impl Geolocator for UnreachableGeolocator {
    async fn locate(&self, _ip: &IpAddress) -> Result<Option<IpGeolocation>, DomainError> {
        Err(DomainError::infra_msg("geolocation unreachable"))
    }
}

/// Geolocator that places every address in the same spot, or nowhere.
#[derive(Default)]
pub struct FakeGeolocator {
    /// The location every lookup returns.
    pub location: Option<IpGeolocation>,
}

#[async_trait]
impl Geolocator for FakeGeolocator {
    async fn locate(&self, _ip: &IpAddress) -> Result<Option<IpGeolocation>, DomainError> {
        Ok(self.location.clone())
    }
}

/// One recorded sign-in: who, in which tenant, from where and when.
type RecordedSignIn = (TenantId, UserId, IpGeolocation, time::OffsetDateTime);

/// Sign-in history kept in memory: every sign-in recorded, newest last.
#[derive(Default)]
pub struct FakeSignInHistory {
    places: Mutex<Vec<RecordedSignIn>>,
}

impl FakeSignInHistory {
    /// How many sign-ins have been recorded, across tenants.
    #[must_use]
    pub fn recorded(&self) -> usize {
        self.places.lock().unwrap().len()
    }
}

impl TenantScoped for FakeSignInHistory {}

#[async_trait]
impl SignInHistoryStore for FakeSignInHistory {
    async fn history(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<SignInHistory, DomainError> {
        let places = self.places.lock().unwrap();
        let theirs: Vec<_> = places
            .iter()
            .filter(|(held_in, who, _, _)| held_in == &**tenant_id && who == user_id)
            .collect();
        let mut countries = Vec::new();
        for code in theirs.iter().map(|(_, _, place, _)| place.country_code()) {
            if !countries.contains(code) {
                countries.push(code.clone());
            }
        }
        let last = theirs.last().map(|(_, _, place, at)| (place.clone(), *at));
        Ok(SignInHistory::new(countries, Fact::from_option(last)))
    }

    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        place: &IpGeolocation,
        at: time::OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.places
            .lock()
            .unwrap()
            .push((**tenant_id, *user_id, place.clone(), at));
        Ok(())
    }
}

/// In-memory break-glass grants and policies, each kept in the tenant it
/// names as it was last saved.
#[derive(Default)]
pub struct FakeBreakGlassStore {
    grants: Mutex<Vec<BreakGlassGrant>>,
    policies: Mutex<Vec<BreakGlassPolicy>>,
}

impl TenantScoped for FakeBreakGlassStore {}

impl FakeBreakGlassStore {
    /// No grants and no policies.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Holds `grants`, each in the tenant it names.
    #[must_use]
    pub fn holding(grants: impl IntoIterator<Item = BreakGlassGrant>) -> Self {
        let store = Self::default();
        store.grants.lock().unwrap().extend(grants);
        store
    }

    /// How many grants are held, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.grants.lock().unwrap().len()
    }

    fn grants_in(&self, tenant_id: &ScopedTenant) -> Vec<BreakGlassGrant> {
        self.grants
            .lock()
            .unwrap()
            .iter()
            .filter(|grant| grant.tenant_id() == &**tenant_id)
            .map(copy_grant)
            .collect()
    }
}

#[async_trait]
impl BreakGlassStore for FakeBreakGlassStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &BreakGlassGrantId,
    ) -> Result<Option<BreakGlassGrant>, DomainError> {
        Ok(self
            .grants_in(tenant_id)
            .into_iter()
            .find(|grant| grant.id() == id))
    }

    async fn list(&self, tenant_id: &ScopedTenant) -> Result<Vec<BreakGlassGrant>, DomainError> {
        Ok(self.grants_in(tenant_id))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        grant: &BreakGlassGrant,
    ) -> Result<(), DomainError> {
        if grant.tenant_id() != &**tenant_id {
            return Err(DomainError::infra_msg(
                "a grant saved through another tenant's store",
            ));
        }
        let mut grants = self.grants.lock().unwrap();
        grants.retain(|held| held.id() != grant.id());
        grants.push(copy_grant(grant));
        Ok(())
    }

    async fn find_policy(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<BreakGlassPolicy>, DomainError> {
        Ok(self
            .policies
            .lock()
            .unwrap()
            .iter()
            .find(|policy| policy.tenant_id() == &**tenant_id)
            .map(copy_policy))
    }

    async fn save_policy(
        &self,
        tenant_id: &ScopedTenant,
        policy: &BreakGlassPolicy,
    ) -> Result<(), DomainError> {
        if policy.tenant_id() != &**tenant_id {
            return Err(DomainError::infra_msg(
                "a policy saved through another tenant's store",
            ));
        }
        let mut policies = self.policies.lock().unwrap();
        policies.retain(|held| held.tenant_id() != policy.tenant_id());
        policies.push(copy_policy(policy));
        Ok(())
    }
}

/// A copy of `grant`, which does not implement `Clone`.
fn copy_grant(grant: &BreakGlassGrant) -> BreakGlassGrant {
    BreakGlassGrant::reconstitute(BreakGlassGrantRow {
        id: *grant.id(),
        tenant_id: *grant.tenant_id(),
        user_id: *grant.user_id(),
        grantee_person: grant.grantee_person().clone(),
        access: grant.access().clone(),
        reason: grant.reason().clone(),
        approved_by: grant.approved_by().clone(),
        expires_at: grant.expires_at(),
        revocation: Revocation::from_stored(grant.revoked_at()),
        created_at: grant.created_at(),
    })
    .expect("a live grant's own row rebuilds")
}

/// A copy of `policy`, which does not implement `Clone`.
fn copy_policy(policy: &BreakGlassPolicy) -> BreakGlassPolicy {
    BreakGlassPolicy::reconstitute(BreakGlassPolicyRow {
        tenant_id: *policy.tenant_id(),
        self_service: policy.self_service().clone(),
        updated_at: policy.updated_at(),
    })
    .expect("a live policy's own row rebuilds")
}

impl Fake for Arc<dyn UserLookup> {
    fn fake() -> Self {
        Arc::new(FakeUserLookup::empty())
    }
}

impl Fake for Arc<dyn SignInAttemptCounts> {
    fn fake() -> Self {
        Arc::new(FakeSignInAttemptCounts::default())
    }
}

impl Fake for Arc<dyn Pause> {
    fn fake() -> Self {
        Arc::new(RecordingPause::default())
    }
}

impl Fake for Arc<dyn BindThrottle> {
    fn fake() -> Self {
        Arc::new(AllowingThrottle)
    }
}

impl Fake for Arc<dyn CredentialBreachChecker> {
    fn fake() -> Self {
        Arc::new(FakeBreachChecker::default())
    }
}

impl Fake for Arc<dyn Geolocator> {
    fn fake() -> Self {
        Arc::new(FakeGeolocator::default())
    }
}

impl Fake for Arc<dyn SignInHistoryStore> {
    fn fake() -> Self {
        Arc::new(FakeSignInHistory::default())
    }
}

impl Fake for Arc<dyn BreakGlassStore> {
    fn fake() -> Self {
        Arc::new(FakeBreakGlassStore::empty())
    }
}
