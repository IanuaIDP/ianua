//! Fakes for signing people in on the hosts of apps behind the gateway.

use std::collections::BTreeMap;
use std::num::NonZeroU8;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::handoff::{SessionHandoff, SessionHandoffRow};
use ianua_domain::domains::authentication::sessions::mfa_challenge::{
    MfaChallenge, MfaChallengeRow,
};
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::sign_in::accepted::{
    AcceptedSignIn, CookieHosts, SignInDelivery,
};
use ianua_domain::domains::routing::sign_in::app::{
    AppSignIn, AppSignInParams, SignInAction, SignInPath, SignedOutBrowsers,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    DomainName, Fact, HttpsUrl, Lifetime, Nonce, ServiceId, Setting, TenantId, TokenHash,
    TrustedDeviceId, Usage, UserId,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::authentication::{
    AppAccessGrant, AppSessionCheck, AppSessionClaim, AppSessionGrant, AppSessionTokens,
    HandoffStore, IssuedAppSession, MfaChallengeStore, NonceLedger, RequestSeal,
};
use crate::ports::routing::ServiceStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::{FakeSessionStore, password_session};
use crate::test_support::organization::{org_store_with, test_org};
use crate::test_support::routing::{
    FakeServiceStore, pinned_upstream, routing_admin, service_named,
};
use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_ctx};
use crate::use_cases::authentication::app_sign_in::{
    AcrossHosts, AcrossHostsPorts, AppSignInContext, AppSignInLifetimes, TargetPorts,
};

/// App session check that answers whatever its switch says: live while it
/// is set, ended once a test clears it.
pub struct FakeAppSessionCheck(pub AtomicBool);

impl TenantScoped for FakeAppSessionCheck {}

#[async_trait]
impl AppSessionCheck for FakeAppSessionCheck {
    async fn live_until(
        &self,
        _: &ScopedTenant,
        _: &AppSessionClaim,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        let live = self.0.load(Ordering::SeqCst);
        Ok(live.then(|| clock::now().saturating_add(time::Duration::hours(1))))
    }
}

/// Mints readable stand-ins and reads back the one claim it holds.
#[derive(Default)]
pub struct FakeAppSessionTokens {
    /// The claim every token reads back as, or none to refuse every token.
    pub claim: Mutex<Option<AppSessionClaim>>,
    /// The tokens minted, in order.
    pub minted: Mutex<Vec<String>>,
    /// The trusted device each session token minted names, in order.
    pub named_devices: Mutex<Vec<Fact<TrustedDeviceId>>>,
}

impl FakeAppSessionTokens {
    fn mint(&self, token: String, expires_at: time::OffsetDateTime) -> IssuedAppSession {
        self.minted.lock().unwrap().push(token.clone());
        IssuedAppSession {
            token: Secret::new(token),
            expires_at,
        }
    }
}

#[async_trait]
impl AppSessionTokens for FakeAppSessionTokens {
    async fn issue(
        &self,
        _: &ScopedTenant,
        grant: &AppSessionGrant,
    ) -> Result<IssuedAppSession, DomainError> {
        let token = format!("session:{}:{}", grant.host, grant.audience);
        self.named_devices
            .lock()
            .unwrap()
            .push(grant.signed_in_from);
        Ok(self.mint(token, grant.expires_at))
    }

    async fn issue_access(
        &self,
        _: &ScopedTenant,
        grant: &AppAccessGrant,
    ) -> Result<IssuedAppSession, DomainError> {
        let token = format!("access:{}:{}", grant.audience, grant.owner);
        Ok(self.mint(token, grant.expires_at))
    }

    async fn read(
        &self,
        _: &ScopedTenant,
        _: &Secret,
        _: &DomainName,
    ) -> Result<AppSessionClaim, DomainError> {
        self.claim
            .lock()
            .unwrap()
            .ok_or_else(|| DomainError::unauthorized("no session"))
    }
}

/// In-memory handoff store that hands each saved handoff out once, and only
/// to the tenant it was saved in.
#[derive(Default)]
pub struct FakeHandoffStore {
    kept: Mutex<Vec<(TenantId, SessionHandoff<ResolvedTenant>)>>,
}

impl FakeHandoffStore {
    /// How many handoffs are waiting to be taken, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.kept.lock().unwrap().len()
    }
}

impl TenantScoped for FakeHandoffStore {}

#[async_trait]
impl HandoffStore for FakeHandoffStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        handoff: &SessionHandoff<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.kept
            .lock()
            .unwrap()
            .push((**tenant_id, copy_handoff(handoff)));
        Ok(())
    }

    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<SessionHandoff<ResolvedTenant>>, DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let at = kept.iter().position(|(held_in, handoff)| {
            held_in == &**tenant_id && handoff.token_hash() == token_hash
        });
        Ok(at.map(|at| kept.remove(at).1))
    }
}

/// A copy of `handoff`, which does not implement `Clone`.
fn copy_handoff(handoff: &SessionHandoff<ResolvedTenant>) -> SessionHandoff<ResolvedTenant> {
    SessionHandoff::reconstitute(SessionHandoffRow {
        token_hash: handoff.token_hash().clone(),
        browser_hash: handoff.browser_hash().clone(),
        session_id: *handoff.session_id(),
        service_id: *handoff.service_id(),
        host: handoff.host().clone(),
        expires_at: handoff.expires_at(),
        usage: Usage::from_stored(handoff.consumed_at()),
    })
    .expect("a live handoff's own row rebuilds")
}

/// In-memory app sign-in second-factor challenges, keyed by tenant and
/// token hash and kept as last saved so wrong codes stay counted.
#[derive(Default)]
pub struct FakeMfaChallengeStore {
    challenges: Mutex<Vec<(TenantId, MfaChallenge<ResolvedTenant>)>>,
}

impl FakeMfaChallengeStore {
    /// How many challenges are open, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.challenges.lock().unwrap().len()
    }
}

/// A copy of `challenge`, which does not implement `Clone`.
fn copy_challenge(challenge: &MfaChallenge<ResolvedTenant>) -> MfaChallenge<ResolvedTenant> {
    MfaChallenge::reconstitute(MfaChallengeRow {
        token_hash: challenge.token_hash().clone(),
        session_id: *challenge.session_id(),
        expires_at: challenge.expires_at(),
        failed_attempts: challenge.failed_attempts(),
        usage: Usage::from_stored(challenge.consumed_at()),
    })
    .expect("a live challenge's own row rebuilds")
}

impl TenantScoped for FakeMfaChallengeStore {}

#[async_trait]
impl MfaChallengeStore for FakeMfaChallengeStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        challenge: &MfaChallenge<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.retain(|(held_in, held)| {
            !(held_in == &**tenant_id && held.token_hash() == challenge.token_hash())
        });
        challenges.push((**tenant_id, copy_challenge(challenge)));
        Ok(())
    }

    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<MfaChallenge<ResolvedTenant>>, DomainError> {
        Ok(self
            .challenges
            .lock()
            .unwrap()
            .iter()
            .find(|(held_in, held)| held_in == &**tenant_id && held.token_hash() == token_hash)
            .map(|(_, held)| copy_challenge(held)))
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<(), DomainError> {
        self.challenges.lock().unwrap().retain(|(held_in, held)| {
            !(held_in == &**tenant_id && held.token_hash() == token_hash)
        });
        Ok(())
    }
}

/// In-memory nonce ledger that accepts each nonce only the first time.
#[derive(Default)]
pub struct FakeNonceLedger {
    spent: Mutex<Vec<Nonce>>,
}

impl FakeNonceLedger {
    /// How many nonces have been spent.
    #[must_use]
    pub fn spent(&self) -> usize {
        self.spent.lock().unwrap().len()
    }
}

#[async_trait]
impl NonceLedger for FakeNonceLedger {
    async fn spend(&self, nonce: &Nonce, _ttl: Lifetime) -> bool {
        let mut spent = self.spent.lock().unwrap();
        if spent.contains(nonce) {
            return false;
        }
        spent.push(nonce.clone());
        true
    }
}

/// Seals a body as `tag:` followed by its length, and an answer as
/// `answer:`, the question's nonce and its length: enough to tell a sealed
/// body from one whose length was altered, and an answer bound to one
/// question from one bound to another, which is all the tests depend on.
pub struct TagSeal;

impl RequestSeal for TagSeal {
    fn seal(&self, body: &[u8]) -> String {
        format!("tag:{}", body.len())
    }

    fn verifies(&self, body: &[u8], seal: &str) -> bool {
        self.seal(body) == seal
    }

    fn seal_answer(&self, nonce: &Nonce, body: &[u8]) -> String {
        format!("answer:{}:{}", nonce.as_str(), body.len())
    }

    fn verifies_answer(&self, nonce: &Nonce, body: &[u8], seal: &str) -> bool {
        self.seal_answer(nonce, body) == seal
    }
}

/// The host the test shop signs people in on.
pub const SHOP_HOST: &str = "shop.example.com";

/// App sign-in on `hosts`, with each action moved as `moved` says and the
/// rest at the default prefix.
///
/// # Panics
///
/// If a host is not a valid name or the settings are refused. Tests pass
/// settings that hold.
#[must_use]
pub fn app_sign_in_on(hosts: &[&str], moved: BTreeMap<SignInAction, SignInPath>) -> AppSignIn {
    AppSignIn::new(AppSignInParams {
        hosts: hosts
            .iter()
            .map(|host| DomainName::new(*host).expect("a valid host"))
            .collect(),
        prefix: Setting::Unset,
        moved,
        after_sign_in: Setting::Unset,
        signed_out_browsers: SignedOutBrowsers::Refuse,
    })
    .expect("the test sign-in settings hold")
}

/// An active service named `shop`, pinning the audience `shop`, that signs
/// people in on [`SHOP_HOST`].
///
/// # Panics
///
/// Never: a routing admin turns app sign-in on for a pinned service.
#[must_use]
pub fn shop_with_app_sign_in() -> Service<ResolvedTenant> {
    let mut shop = service_named("shop", pinned_upstream("https://shop.example.com", "shop"));
    shop.change_app_sign_in(
        Setting::Set(app_sign_in_on(&[SHOP_HOST], BTreeMap::new())),
        &routing_admin(),
    )
    .expect("a routing admin turns app sign-in on");
    shop
}

/// An active service named `name`, pinning the audience `name`, that
/// accepts `owner`'s sign-in delivered as `delivery`.
///
/// # Panics
///
/// Never: a routing admin makes a pinned service accept another's sign-in.
#[must_use]
pub fn accepting_sign_in_of(
    owner: &ServiceId,
    name: &str,
    delivery: SignInDelivery,
) -> Service<ResolvedTenant> {
    let mut service = service_named(name, pinned_upstream("https://app.example.com", name));
    service
        .accept_app_sign_in_of(
            Setting::Set(AcceptedSignIn::new(*owner, delivery)),
            &routing_admin(),
        )
        .expect("a routing admin makes the service accept the sign-in");
    service
}

/// A service store holding `services` in the tenant [`test_ctx`] carries.
///
/// # Panics
///
/// Never: the fake store keeps whatever it is given.
///
/// [`test_ctx`]: crate::test_support::test_ctx
#[must_use]
pub fn app_sign_in_services(
    services: impl IntoIterator<Item = Service<ResolvedTenant>>,
) -> Arc<FakeServiceStore> {
    let store = Arc::new(FakeServiceStore::empty());
    let tenant = test_ctx().tenant();
    for service in services {
        block_on(store.save(&tenant, &service)).expect("the fake store keeps it");
    }
    store
}

/// The stores an app sign-in resolves against: the test tenant, its
/// organization `acme`, and `services`.
#[must_use]
pub fn app_sign_in_target_ports(services: Arc<FakeServiceStore>) -> TargetPorts {
    TargetPorts {
        tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
        org_store: org_store_with([test_org(test_ctx().organization_id(), "acme")]),
        service_store: services,
    }
}

/// Lifetimes for the short steps of an app sign-in: five minutes for a
/// challenge with three wrong codes, a minute for a hop, five minutes for
/// a token.
///
/// # Panics
///
/// Never: the lifetimes are positive.
#[must_use]
pub fn app_sign_in_lifetimes() -> AppSignInLifetimes {
    let minutes = |count: i64| Lifetime::seconds(count * 60).expect("a positive lifetime");
    AppSignInLifetimes {
        mfa_challenge: minutes(5),
        mfa_challenge_attempts: NonZeroU8::new(3).expect("three is not zero"),
        handoff: minutes(1),
        access: minutes(5),
    }
}

/// A shop signing people in on [`SHOP_HOST`], an `api` service accepting
/// its sign-in with a cookie of its own on `api.example.com` and
/// `files.example.com`, a `reports` service taking tokens from it, and a
/// finished session bound to the shop, with the fakes a test reads back.
pub struct CrossHostFixture {
    /// The cross-host flows under test.
    pub across: AcrossHosts,
    /// The stores the services are resolved from.
    pub ports: TargetPorts,
    /// The tokens minted.
    pub tokens: Arc<FakeAppSessionTokens>,
    /// The one-time codes waiting.
    pub handoffs: Arc<FakeHandoffStore>,
    /// Whether the session still counts.
    pub live: Arc<FakeAppSessionCheck>,
    /// What was recorded.
    pub audit: Arc<FakeEventDispatcher>,
    /// The shop, whose sign-in it is.
    pub owner: ServiceId,
    /// The API accepting it with a cookie of its own.
    pub api: ServiceId,
}

/// [`CrossHostFixture`], everything live.
///
/// # Panics
///
/// Never: the fixture's records are consistent.
#[must_use]
pub fn cross_host_fixture() -> CrossHostFixture {
    let (ports, owner, api) = cross_host_services();
    let session = app_session(owner);
    let tokens = Arc::new(reading_back(&session, owner));
    let handoffs = Arc::new(FakeHandoffStore::default());
    let live = Arc::new(FakeAppSessionCheck(AtomicBool::new(true)));
    let across = AcrossHosts::new(
        AcrossHostsPorts {
            target: ports.clone(),
            session_store: Arc::new(FakeSessionStore::with_session(session)),
            tokens: tokens.clone(),
            handoff_store: handoffs.clone(),
            session_check: live.clone(),
            ..AcrossHostsPorts::fakes()
        },
        HttpsUrl::new("https://ianua.example.com").expect("a valid address"),
        app_sign_in_lifetimes(),
    );
    CrossHostFixture {
        across,
        ports,
        tokens,
        handoffs,
        live,
        audit: Arc::new(FakeEventDispatcher::new()),
        owner,
        api,
    }
}

/// A finished sign-in of a new person, bound to the app `owner`.
fn app_session(owner: ServiceId) -> Session<ResolvedTenant> {
    let mut session = password_session(UserId::new(), "hash", SecondFactor::NotOwed);
    session
        .bind_to_app(owner)
        .expect("a dashboard session binds");
    session
}

/// The shop, the API keeping a cookie of its own and the reports service
/// taking tokens, stored, with the shop's and the API's ids.
fn cross_host_services() -> (TargetPorts, ServiceId, ServiceId) {
    let shop = shop_with_app_sign_in();
    let owner = *shop.id();
    let cookie_hosts = ["api.example.com", "files.example.com"]
        .iter()
        .map(|host| DomainName::new(*host).expect("a valid host"))
        .collect();
    let own_cookie = CookieHosts::new(cookie_hosts).expect("two distinct hosts");
    let api = accepting_sign_in_of(&owner, "api", SignInDelivery::OwnCookie(own_cookie));
    let api_id = *api.id();
    let reports = accepting_sign_in_of(&owner, "reports", SignInDelivery::Tokens);
    let ports = app_sign_in_target_ports(app_sign_in_services([shop, api, reports]));
    (ports, owner, api_id)
}

/// Tokens that read back as `session`, opened by `owner`'s sign-in.
fn reading_back(session: &Session<ResolvedTenant>, owner: ServiceId) -> FakeAppSessionTokens {
    FakeAppSessionTokens {
        claim: Mutex::new(Some(AppSessionClaim {
            session_id: *session.id(),
            user_id: *session.user_id(),
            service_id: owner,
            idle_timeout: None,
            signed_in_from: session.signed_in_from(),
        })),
        ..FakeAppSessionTokens::default()
    }
}

/// A request from nowhere in particular to `service_id`'s sign-in on
/// `host`, in the tenant [`test_ctx`] carries.
///
/// # Panics
///
/// If `host` is not a valid name. Tests pass ones that are.
#[must_use]
pub fn cross_host_ctx(service_id: ServiceId, host: &str) -> AppSignInContext {
    AppSignInContext {
        tenant: test_ctx().tenant(),
        service_id,
        host: DomainName::new(host).expect("a valid host"),
        ip_address: None,
        user_agent: None,
    }
}

impl Fake for Arc<dyn AppSessionCheck> {
    fn fake() -> Self {
        Arc::new(FakeAppSessionCheck(AtomicBool::new(true)))
    }
}

impl Fake for Arc<dyn AppSessionTokens> {
    fn fake() -> Self {
        Arc::new(FakeAppSessionTokens::default())
    }
}

impl Fake for Arc<dyn HandoffStore> {
    fn fake() -> Self {
        Arc::new(FakeHandoffStore::default())
    }
}

impl Fake for Arc<dyn MfaChallengeStore> {
    fn fake() -> Self {
        Arc::new(FakeMfaChallengeStore::default())
    }
}

impl Fake for Arc<dyn NonceLedger> {
    fn fake() -> Self {
        Arc::new(FakeNonceLedger::default())
    }
}

impl Fake for Arc<dyn RequestSeal> {
    fn fake() -> Self {
        Arc::new(TagSeal)
    }
}
