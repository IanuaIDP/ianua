//! Answers to what a use case asks `acting`, as a test says them: what a
//! caller holds in a tenant, who signed in, who acts on an organization and
//! what an operator may do. No records are loaded; the domain's proofs are
//! made from what the test names.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::token_attack::{AssertionFault, SignInRefusal};
use ianua_domain::domains::authentication::sessions::account_check::SessionCheck;
use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
use ianua_domain::domains::authentication::sessions::session::{
    Session, SessionOrigin, SessionRow,
};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::authentication::sessions::timeout::{IdleTimeout, SessionTimeoutPolicy};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{CustomPermission, SystemPermission};
use ianua_domain::domains::consumers::authority::ConsumerAuthority;
use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::domains::operator::control::{OperatorAuthority, OperatorSignIn};
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::domains::organization::access::api_key::{
    MintedThrough, OrgApiKey, OrgApiKeyRow, OrgApiKeyStatus,
};
use ianua_domain::domains::organization::access::session::{
    OrgSession, OrgSessionRow, SessionPlace,
};
use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
use ianua_domain::domains::organization::lifecycle::{CreateOrganizationParams, Organization};
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::members::org_user::{OrgPassword, OrgUser, OrgUserRow};
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{
    Audience, CredentialChange, DisplayName, Email, Expiry, Fact, Human, HumanAccount, Joining,
    KeyPrefix, Label, Lifetime, OrgApiKeyId, OrgUserId, OrganizationId, PersonKey, Preference,
    Scope, SessionId, TenantId, TenantSlug, TokenHash, UserId,
};

use crate::acting::agent::{AgentActing, AgentActingPorts, RefusedSignIn, SignInAttempt};
use crate::acting::consumer::{ConsumerActing, ConsumerActingPorts};
use crate::acting::organization::{Held, OrgActor};
use crate::acting::tenant::{AccountHolder, SignedInAccount, credential_refusal};
use crate::acting::{
    AgentActors, ConsumerAuthorities, OperatorAuthorities, OrgActors, TenantAuthorities,
};
use crate::context::{
    AgentAssertion, CallerContext, CallerIdentity, ConsumerCaller, Credential, OperatorCaller,
    OrgCaller,
};
use crate::error::AppError;
use crate::tenancy::ScopedTenant;
use crate::test_support::consumers::{billing_sync, consumer_holding, test_key_digest};
use crate::test_support::identity::stored_user;
use crate::test_support::organization::{OrgShape, as_stored, org_shaped, password_only};
use crate::test_support::{Fake, test_session_id};

/// The address every person a fake names signs in with.
const CALLER_ADDRESS: &str = "caller@example.test";

/// Why a fake turns a caller away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Their session or key no longer counts.
    SignedOut,
    /// They may not act here at all.
    Forbidden,
}

impl Refusal {
    fn error(self) -> AppError {
        match self {
            Self::SignedOut => AppError::Unauthenticated,
            Self::Forbidden => {
                AppError::Forbidden("the test refuses this caller".to_owned().into())
            }
        }
    }
}

/// What a caller holds in their tenant, as a test says.
pub struct FakeTenantAuthorities {
    answer: Result<TenantRights, Refusal>,
    sign_in: SignInProgressRow,
}

/// The built-in and app permissions a fake says a caller holds.
struct TenantRights {
    system: Vec<SystemPermission>,
    custom: Vec<CustomPermission>,
}

impl FakeTenantAuthorities {
    /// Every caller holds `system` in their tenant, and nothing else.
    #[must_use]
    pub fn holding(system: &[SystemPermission]) -> Self {
        Self::holding_with_app(system, &[])
    }

    /// Every caller holds `system` and the app permissions `custom` in
    /// their tenant, and nothing else.
    #[must_use]
    pub fn holding_with_app(system: &[SystemPermission], custom: &[CustomPermission]) -> Self {
        Self {
            answer: Ok(TenantRights {
                system: system.to_vec(),
                custom: custom.to_vec(),
            }),
            sign_in: password_only(),
        }
    }

    /// Every caller holds every system permission in their tenant.
    #[must_use]
    pub fn holding_everything() -> Self {
        Self::holding(SystemPermission::all())
    }

    /// Every caller is turned away, for `refusal`.
    #[must_use]
    pub fn refusing(refusal: Refusal) -> Self {
        Self {
            answer: Err(refusal),
            sign_in: password_only(),
        }
    }

    /// The same answers, with every session signed in as `progress` says:
    /// how, with which factor, and what it still owes. A finished
    /// password sign-in otherwise.
    #[must_use]
    pub fn signed_in_by(self, progress: SignInProgressRow) -> Self {
        Self {
            sign_in: progress,
            ..self
        }
    }

    fn rights(&self) -> Result<&TenantRights, AppError> {
        self.answer.as_ref().map_err(|refusal| refusal.error())
    }
}

#[async_trait]
impl TenantAuthorities for FakeTenantAuthorities {
    async fn authority(&self, caller: &CallerContext) -> Result<TenantAuthority, AppError> {
        let held = self.rights()?;
        let who = person_acting(caller)?;
        Ok(TenantAuthority::assumed(
            who,
            caller.tenant_id(),
            &held.system,
            &held.custom,
        ))
    }

    async fn signed_in(&self, caller: &CallerContext) -> Result<SignedInAccount, AppError> {
        self.rights()?;
        let (CallerIdentity::TenantUser(user_id), Credential::TenantSession(session_id)) =
            (caller.identity(), caller.credential())
        else {
            return Err(AppError::Unauthenticated);
        };
        let session = fresh_session(*user_id, *session_id, self.sign_in);
        Ok(signed_in_account(session))
    }

    async fn holder(&self, caller: &CallerContext) -> Result<AccountHolder, AppError> {
        self.rights()?;
        match (caller.identity(), caller.credential()) {
            (CallerIdentity::TenantUser(_), Credential::TenantSession(_)) => {
                let person = self.signed_in(caller).await?;
                Ok(AccountHolder::Session(Box::new(person)))
            }
            (CallerIdentity::TenantUser(user_id), Credential::DirectoryBind(_)) => {
                Ok(AccountHolder::Directory(Box::new(stored_user(
                    *user_id,
                    CALLER_ADDRESS,
                    UserStatus::Active,
                ))))
            }
            _ => Err(AppError::Unauthenticated),
        }
    }

    async fn signed_in_on(
        &self,
        _: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<SignedInAccount, AppError> {
        self.rights()?;
        let session = fresh_session(UserId::new(), *session_id, self.sign_in);
        Ok(signed_in_account(session))
    }
}

/// What a caller holds in their tenant, as a test says, changed by the test
/// while something holds on to it, such as rights taken away while a stream
/// is open.
pub struct ChangingTenantAuthorities {
    current: std::sync::Mutex<Arc<FakeTenantAuthorities>>,
}

impl ChangingTenantAuthorities {
    /// Answers as `first` until changed.
    #[must_use]
    pub fn starting(first: FakeTenantAuthorities) -> Self {
        Self {
            current: std::sync::Mutex::new(Arc::new(first)),
        }
    }

    /// Answers as `next` from now on.
    pub fn change_to(&self, next: FakeTenantAuthorities) {
        *self.current.lock().unwrap() = Arc::new(next);
    }

    fn now(&self) -> Arc<FakeTenantAuthorities> {
        Arc::clone(&self.current.lock().unwrap())
    }
}

#[async_trait]
impl TenantAuthorities for ChangingTenantAuthorities {
    async fn authority(&self, caller: &CallerContext) -> Result<TenantAuthority, AppError> {
        self.now().authority(caller).await
    }

    async fn signed_in(&self, caller: &CallerContext) -> Result<SignedInAccount, AppError> {
        self.now().signed_in(caller).await
    }

    async fn holder(&self, caller: &CallerContext) -> Result<AccountHolder, AppError> {
        self.now().holder(caller).await
    }

    async fn signed_in_on(
        &self,
        tenant: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<SignedInAccount, AppError> {
        self.now().signed_in_on(tenant, session_id).await
    }
}

impl Fake for Arc<dyn TenantAuthorities> {
    fn fake() -> Self {
        Arc::new(FakeTenantAuthorities::holding_everything())
    }
}

/// The person a caller acts as: the user they impersonate, or themselves.
/// A credential that never acts inside a tenant, such as an organization
/// key, is turned away as the real resolver turns it away.
fn person_acting(caller: &CallerContext) -> Result<Human, AppError> {
    let account = match (caller.identity(), caller.credential()) {
        (CallerIdentity::Operator(_), Credential::Impersonation { user, .. }) => {
            HumanAccount::User(*user)
        }
        (
            CallerIdentity::TenantUser(user),
            Credential::TenantSession(_)
            | Credential::TenantApiKey(_)
            | Credential::DirectoryBind(_),
        ) => HumanAccount::User(*user),
        (CallerIdentity::OrgUser(member), Credential::OrgSession(_)) => {
            HumanAccount::OrgUser(*member)
        }
        (_, credential) => return Err(credential_refusal(credential)),
    };
    Ok(Human::new(account, person_key()))
}

fn person_key() -> PersonKey {
    PersonKey::new(CALLER_ADDRESS).expect("the caller address is valid")
}

/// The account `session` belongs to, signed in to it. The session must pass
/// the domain's own session check.
fn signed_in_account(session: Session<ResolvedTenant>) -> SignedInAccount {
    let account = stored_user(*session.user_id(), CALLER_ADDRESS, UserStatus::Active);
    let timeout = session_timeout();
    let check = SessionCheck {
        account: &account,
        timeout: &timeout,
        now: clock::now(),
    };
    let signed_in = session
        .signed_in(&check)
        .expect("a fresh, finished session of an active account passes its check");
    SignedInAccount {
        account,
        signed_in,
        session,
        timeout,
    }
}

fn session_timeout() -> SessionTimeoutPolicy {
    let hours = |count: i64| Lifetime::seconds(count * 3600).expect("a valid lifetime");
    SessionTimeoutPolicy::new(hours(8), IdleTimeout::After(hours(1)))
        .expect("an idle timeout shorter than the session")
}

fn fresh_session(
    user_id: UserId,
    id: SessionId,
    progress: SignInProgressRow,
) -> Session<ResolvedTenant> {
    let now = clock::now();
    Session::reconstitute(SessionRow {
        id,
        user_id,
        refresh_token_hash: TokenHash::from_stored("refresh".to_owned()),
        parent_id: SessionOrigin::SignIn,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        signed_in_from: Fact::Unknown,
        progress,
        status: SessionStatus::Active,
        channel: SessionChannel::Dashboard,
        signed_in_at: now,
        created_at: now,
        last_active_at: now,
        expires_at: now + time::Duration::hours(8),
        kept_through: CredentialChange::Never,
        last_use: Fact::Unknown,
    })
    .expect("a fresh, finished session is a consistent row")
}

/// Who acts on an organization, as a test says: the caller, as an active
/// member in one role, signed in to a fresh session or acting through a key
/// they minted.
pub struct FakeOrgActors {
    answer: Result<OrgRole, Refusal>,
    through: Through,
    standing: Standing,
}

/// How the fake member's organization stands.
#[derive(Clone)]
enum Standing {
    /// Freshly founded on the free plan, owning no tenant.
    Founded,
    /// As the shape says.
    Shaped(OrgShape),
}

/// What a fake member acts through.
#[derive(Clone)]
enum Through {
    /// A fresh session, signed in as the row says.
    Session(SignInProgressRow),
    /// An active key of theirs carrying these scopes.
    Key(Vec<Scope>),
}

impl FakeOrgActors {
    /// Every caller is an active member in `role`, signed in to a finished
    /// password session.
    #[must_use]
    pub fn in_role(role: OrgRole) -> Self {
        Self {
            answer: Ok(role),
            through: Through::Session(password_only()),
            standing: Standing::Founded,
        }
    }

    /// Every caller is an active member in `role`, acting through a key of
    /// theirs carrying `scopes`. A key always carries something, so with
    /// no scopes named it carries only reading notifications, which no
    /// use case but the notification ones asks for.
    ///
    /// # Panics
    ///
    /// Never in practice: the fallback scope is fixed and valid.
    #[must_use]
    pub fn through_key(role: OrgRole, scopes: Vec<Scope>) -> Self {
        let scopes = match scopes.is_empty() {
            true => vec![Scope::new("org:notifications:view").expect("a valid scope")],
            false => scopes,
        };
        Self {
            answer: Ok(role),
            through: Through::Key(scopes),
            standing: Standing::Founded,
        }
    }

    /// Every caller is turned away, for `refusal`.
    #[must_use]
    pub fn refusing(refusal: Refusal) -> Self {
        Self {
            answer: Err(refusal),
            through: Through::Session(password_only()),
            standing: Standing::Founded,
        }
    }

    /// The same answers, with every session signed in as `progress` says.
    #[must_use]
    pub fn signed_in_by(self, progress: SignInProgressRow) -> Self {
        Self {
            through: Through::Session(progress),
            ..self
        }
    }

    /// The same answers, in a Business organization owning `tenants`.
    #[must_use]
    pub fn owning(self, tenants: &[TenantId]) -> Self {
        self.shaped(OrgShape::owning(tenants))
    }

    /// The same answers, in a Business organization standing as `shape`
    /// says: its tenants, sign-in settings and suspension.
    #[must_use]
    pub fn shaped(self, shape: OrgShape) -> Self {
        Self {
            standing: Standing::Shaped(shape),
            ..self
        }
    }
}

#[async_trait]
impl OrgActors for FakeOrgActors {
    async fn actor(&self, caller: &OrgCaller) -> Result<(Organization, OrgActor), AppError> {
        let role = self.answer.map_err(Refusal::error)?;
        let organization = match &self.standing {
            Standing::Founded => organization(caller.organization_id()),
            Standing::Shaped(shape) => org_shaped(caller.organization_id(), shape.clone()),
        };
        let member = member(*caller.member(), caller.organization_id(), role);
        let held = match &self.through {
            Through::Session(progress) => Held::Session(member_session(&member, *progress)),
            Through::Key(scopes) => Held::Key(member_key(&member, scopes.clone())),
        };
        let actor = OrgActor::new(&organization, member, held, clock::now());
        Ok((organization, actor))
    }
}

impl Fake for Arc<dyn OrgActors> {
    fn fake() -> Self {
        Arc::new(FakeOrgActors::in_role(OrgRole::Owner))
    }
}

fn organization(id: OrganizationId) -> Organization {
    let limits = DomainLimits::default();
    Organization::create(CreateOrganizationParams {
        id,
        slug: TenantSlug::new("acme", &limits.slug).expect("a valid slug"),
        name: Label::new("name", "Acme").expect("a valid name"),
        contact_email: Email::new("owner@acme.test").expect("a valid address"),
        display_name: DisplayName::new("Acme", &limits.display_name).expect("a valid name"),
        plan: OrganizationPlan::Free,
    })
    .map(|(organization, _founding)| as_stored(organization))
    .expect("a free organization is founded")
}

fn member(id: OrgUserId, organization_id: OrganizationId, role: OrgRole) -> OrgUser {
    let now = clock::now();
    OrgUser::reconstitute(OrgUserRow {
        id,
        organization_id,
        email: Email::new(CALLER_ADDRESS).expect("a valid address"),
        display_name: DisplayName::new("Test Member", &DomainLimits::default().display_name)
            .expect("a valid name"),
        password_hash: OrgPassword::NotSet,
        status: OrgUserStatus::Active,
        role,
        email_standing: AddressStanding::Verified,
        locale: Preference::Inherited,
        timezone: Preference::Inherited,
        created_at: now,
        updated_at: now,
        joining: Joining::Joined { at: now },
        credentials_changed_at: CredentialChange::Never,
        vouching: Vouching::Absent,
    })
    .expect("an active, joined member is a consistent row")
}

fn member_key(member: &OrgUser, scopes: Vec<Scope>) -> OrgApiKey {
    let now = clock::now();
    OrgApiKey::reconstitute(OrgApiKeyRow {
        id: OrgApiKeyId::new(),
        organization_id: *member.organization_id(),
        name: Label::new("name", "Test key").expect("a valid name"),
        key_prefix: KeyPrefix::new("org_test").expect("a valid prefix"),
        key_hash: TokenHash::from_stored("key".to_owned()),
        scopes,
        created_by: *member.id(),
        minted_through: MintedThrough::Session,
        expires_at: Expiry::Never,
        last_used_at: None,
        status: OrgApiKeyStatus::Active,
        created_at: now,
    })
    .expect("an active key of the member is a consistent row")
}

/// The finished password session `member` signs in to as a
/// [`FakeOrgActors::in_role`] caller, as stored. A test seeds a session
/// store with it when the use case loads the caller's own session.
#[must_use]
pub fn caller_session(member: &OrgUser) -> OrgSession {
    member_session(member, password_only())
}

fn member_session(member: &OrgUser, progress: SignInProgressRow) -> OrgSession {
    let now = clock::now();
    OrgSession::reconstitute(OrgSessionRow {
        id: test_session_id(),
        org_user_id: *member.id(),
        organization_id: *member.organization_id(),
        place: SessionPlace::Tenant(TenantId::new()),
        refresh_token_hash: TokenHash::from_stored("refresh".to_owned()),
        progress,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        status: SessionStatus::Active,
        created_at: now,
        last_active_at: now,
        expires_at: now + time::Duration::hours(8),
        kept_through: CredentialChange::Never,
    })
    .expect("a fresh, finished session is a consistent row")
}

/// What an operator may do on the platform, as a test says.
pub struct FakeOperatorAuthorities {
    answer: Result<(), Refusal>,
}

impl FakeOperatorAuthorities {
    /// Every operator acts with their own key.
    #[must_use]
    pub fn admitting() -> Self {
        Self { answer: Ok(()) }
    }

    /// Every operator is turned away, for `refusal`.
    #[must_use]
    pub fn refusing(refusal: Refusal) -> Self {
        Self {
            answer: Err(refusal),
        }
    }
}

#[async_trait]
impl OperatorAuthorities for FakeOperatorAuthorities {
    async fn authority(&self, caller: &OperatorCaller) -> Result<OperatorAuthority, AppError> {
        self.answer.map_err(Refusal::error)?;
        Ok(OperatorAuthority::assumed(*caller.operator()))
    }

    async fn signed_in(
        &self,
        operator: &Operator,
        _sign_in: &OperatorSignIn,
    ) -> Result<OperatorAuthority, AppError> {
        self.answer.map_err(Refusal::error)?;
        Ok(OperatorAuthority::assumed(*operator.id()))
    }
}

impl Fake for Arc<dyn OperatorAuthorities> {
    fn fake() -> Self {
        Arc::new(FakeOperatorAuthorities::admitting())
    }
}

impl Fake for Arc<dyn AgentActors> {
    fn fake() -> Self {
        Arc::new(AgentActing::new(AgentActingPorts::fakes()))
    }
}

/// What a consumer's roles give it, as a test says: "billing-sync", signed
/// in with its own key, holding what the test names.
pub struct FakeConsumerAuthorities {
    answer: Result<Vec<SystemPermission>, Refusal>,
}

impl FakeConsumerAuthorities {
    /// A consumer whose roles give it `held`.
    #[must_use]
    pub fn holding(held: &[SystemPermission]) -> Self {
        Self {
            answer: Ok(held.to_vec()),
        }
    }

    /// A consumer turned away as `refusal` says.
    #[must_use]
    pub fn refusing(refusal: Refusal) -> Self {
        Self {
            answer: Err(refusal),
        }
    }
}

#[async_trait]
impl ConsumerAuthorities for FakeConsumerAuthorities {
    async fn authority(&self, caller: &ConsumerCaller) -> Result<ConsumerAuthority, AppError> {
        let held = self.answer.as_ref().map_err(|refusal| refusal.error())?;
        let consumer = billing_sync();
        let signed_in = consumer
            .sign_in_with_key(&test_key_digest())
            .map_err(AppError::from_domain)?;
        let records = consumer_holding(consumer.id(), held);
        ConsumerAuthority::of(&consumer, &signed_in, &records.access(**caller.tenant()))
            .map_err(AppError::from_domain)
    }
}

impl Fake for Arc<dyn ConsumerAuthorities> {
    fn fake() -> Self {
        Arc::new(ConsumerActing::new(ConsumerActingPorts::fakes()))
    }
}

/// Turns every agent away, as the sign-in does an assertion that does not
/// verify, was spent before, or names no key of the agent's.
pub struct RefusingAgentActors;

#[async_trait]
impl AgentActors for RefusingAgentActors {
    async fn attempted(
        &self,
        _: &ScopedTenant,
        _: &AgentAssertion,
        _: &Audience,
    ) -> Result<SignInAttempt, AppError> {
        Ok(SignInAttempt::Refused(RefusedSignIn {
            agent: None,
            refusal: SignInRefusal::Assertion(AssertionFault::BadSignature),
        }))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::OperatorId;

    use super::*;
    use crate::test_support::block_on;

    fn came_with(identity: CallerIdentity, credential: Credential) -> CallerContext {
        CallerContext::new(
            identity,
            credential,
            OrganizationId::new(),
            TenantId::new(),
            OrganizationPlan::Free.default_limits(),
        )
        .unwrap()
    }

    /// An organization API key is refused tenant authority even by a fake
    /// configured to grant every tenant permission.
    #[test]
    fn an_organization_key_holds_nothing_inside_a_tenant() {
        let mallory = came_with(
            CallerIdentity::OrgUser(OrgUserId::new()),
            Credential::OrgApiKey(OrgApiKeyId::new()),
        );

        let result = block_on(FakeTenantAuthorities::holding_everything().authority(&mallory));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An operator key without an impersonation grant is refused tenant authority.
    #[test]
    fn an_operator_key_holds_nothing_inside_a_tenant() {
        let mallory = came_with(
            CallerIdentity::Operator(OperatorId::new()),
            Credential::OperatorKey(KeyPrefix::new("opk_mallory").unwrap()),
        );

        let result = block_on(FakeTenantAuthorities::holding_everything().authority(&mallory));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
