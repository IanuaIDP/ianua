//! In-memory organization sessions, and the organizations and sessions
//! sign-in tests start from.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::organization::access::auth_config::{
    OrganizationAuthConfig, OrganizationAuthSettings,
};
use ianua_domain::domains::organization::access::session::{
    OrgSession, OrgSessionRow, SessionPlace,
};
use ianua_domain::domains::organization::billing::negotiated::PlanTerms;
use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
use ianua_domain::domains::organization::lifecycle::{Organization, OrganizationRow};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::status::{OrganizationStatus, Suspension};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CredentialChange, Fact, OrgUserId, OrganizationId, SessionId, TenantId, TokenHash,
};
use time::Duration;

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::organization::{OrgSessionSortField, OrgSessionStore};
use crate::test_support::authentication::RevocationSwitch;
use crate::test_support::listing::page;
use crate::test_support::organization::lifecycle::test_org;
use crate::test_support::{Fake, Revocation};

/// How a sign-in test's organization stands: the tenants it owns, how its
/// members sign in, and who suspended it, if anyone.
#[derive(Clone)]
pub struct OrgShape {
    /// The tenants it owns.
    pub tenants: Vec<TenantId>,
    /// How its members sign in.
    pub settings: OrganizationAuthSettings,
    /// Who suspended it. An organization nobody suspended is active.
    pub suspension: Suspension,
}

impl OrgShape {
    /// An active organization owning `tenants`, signing members in under
    /// the settings a new organization starts with.
    #[must_use]
    pub fn owning(tenants: &[TenantId]) -> Self {
        Self {
            tenants: tenants.to_vec(),
            settings: OrganizationAuthSettings::default(),
            suspension: Suspension::NotSuspended,
        }
    }
}

/// The Business organization `id`, called Acme under the slug `acme-corp`,
/// standing as `shape` says.
///
/// # Panics
///
/// If the settings in `shape` do not hold together.
#[must_use]
pub fn org_shaped(id: OrganizationId, shape: OrgShape) -> Organization {
    let founded = test_org(id, "acme-corp");
    let status = match shape.suspension {
        Suspension::NotSuspended => OrganizationStatus::Active,
        Suspension::ByMember(_) | Suspension::ByPlatform(_) => OrganizationStatus::Suspended,
    };
    Organization::reconstitute(OrganizationRow {
        id,
        slug: founded.slug().clone(),
        name: founded.name().clone(),
        contact_email: founded.contact_email().clone(),
        display_name: founded.display_name().clone(),
        plan: OrganizationPlan::Business,
        terms: PlanTerms::Standard,
        status,
        suspended_by: shape.suspension,
        tenant_ids: shape.tenants,
        auth_config: OrganizationAuthConfig::new(shape.settings)
            .expect("the test's sign-in settings hold together"),
        created_at: founded.created_at(),
        updated_at: founded.updated_at(),
    })
    .expect("a consistent organization row")
}

/// A finished password sign-in that proved no second factor.
#[must_use]
pub fn password_only() -> SignInProgressRow {
    SignInProgressRow {
        method: AuthMethod::Password,
        factor: FactorProved::NoneYet,
        owed: SecondFactor::NotOwed,
    }
}

/// A fresh, active session of `member` working in `tenant_id`, signed in
/// as `progress` says.
///
/// # Panics
///
/// If `progress` is one no sign-in reaches.
#[must_use]
pub fn org_session_of(
    member: &OrgUser,
    tenant_id: TenantId,
    progress: SignInProgressRow,
) -> OrgSession {
    org_session_for(*member.id(), *member.organization_id(), tenant_id, progress)
}

/// A fresh, active session of the member `org_user_id` of
/// `organization_id`, working in `tenant_id`, signed in as `progress` says.
///
/// # Panics
///
/// If `progress` is one no sign-in reaches.
#[must_use]
pub fn org_session_for(
    org_user_id: OrgUserId,
    organization_id: OrganizationId,
    tenant_id: TenantId,
    progress: SignInProgressRow,
) -> OrgSession {
    let opened = Opened {
        org_user_id,
        organization_id,
        place: SessionPlace::Tenant(tenant_id),
        progress,
    };
    session_idle_for(SessionId::new(), opened, Duration::ZERO)
}

/// A fresh, active password session of `member` working on the
/// organization alone, as one a member who reaches no tenant signs in to.
///
/// # Panics
///
/// Never in practice: an active password session is a consistent row.
#[must_use]
pub fn org_session_on_organization(member: &OrgUser) -> OrgSession {
    let opened = Opened {
        org_user_id: *member.id(),
        organization_id: *member.organization_id(),
        place: SessionPlace::Organization,
        progress: password_only(),
    };
    session_idle_for(SessionId::new(), opened, Duration::ZERO)
}

/// The session the test organization member signs in with: the one
/// [`crate::test_support::test_org_caller`] comes with, fresh and active.
#[must_use]
pub fn test_org_session() -> OrgSession {
    test_org_session_idle_for(Duration::ZERO)
}

/// The session the test organization member signs in with, fresh and
/// active, working on the organization alone, as one a member who reaches
/// no tenant signs in to.
///
/// # Panics
///
/// Never in practice: an active password session is a consistent row.
#[must_use]
pub fn test_org_session_on_organization() -> OrgSession {
    let member = crate::test_support::test_org_caller();
    let opened = Opened {
        org_user_id: *member.member(),
        organization_id: member.organization_id(),
        place: SessionPlace::Organization,
        progress: password_only(),
    };
    session_idle_for(
        crate::test_support::test_session_id(),
        opened,
        Duration::ZERO,
    )
}

/// The test organization member's session, signed in `idle` ago and not
/// used since.
///
/// # Panics
///
/// Never in practice: an active password session is a consistent row.
#[must_use]
pub fn test_org_session_idle_for(idle: Duration) -> OrgSession {
    let member = crate::test_support::test_org_caller();
    let opened = Opened {
        org_user_id: *member.member(),
        organization_id: member.organization_id(),
        place: SessionPlace::Tenant(crate::test_support::test_ctx().tenant_id()),
        progress: password_only(),
    };
    session_idle_for(crate::test_support::test_session_id(), opened, idle)
}

/// An active session of the member `org_user_id` of `organization_id`,
/// signed in with a password `idle` ago and not used since.
///
/// # Panics
///
/// Never in practice: an active password session is a consistent row.
#[must_use]
pub fn org_session_idle_for(
    org_user_id: OrgUserId,
    organization_id: OrganizationId,
    idle: Duration,
) -> OrgSession {
    let opened = Opened {
        org_user_id,
        organization_id,
        place: SessionPlace::Tenant(TenantId::new()),
        progress: password_only(),
    };
    session_idle_for(SessionId::new(), opened, idle)
}

/// Whose session a test opens, where, and how it signed in.
#[derive(Clone, Copy)]
struct Opened {
    org_user_id: OrgUserId,
    organization_id: OrganizationId,
    place: SessionPlace,
    progress: SignInProgressRow,
}

fn session_idle_for(id: SessionId, opened: Opened, idle: Duration) -> OrgSession {
    let now = clock::now();
    OrgSession::reconstitute(OrgSessionRow {
        id,
        org_user_id: opened.org_user_id,
        organization_id: opened.organization_id,
        place: opened.place,
        refresh_token_hash: TokenHash::from_stored(format!("refresh-{}", opened.org_user_id)),
        progress: opened.progress,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        status: SessionStatus::Active,
        created_at: now - idle,
        last_active_at: now - idle,
        expires_at: now + Duration::hours(8),
        kept_through: CredentialChange::Never,
    })
    .expect("an active session is a consistent row")
}

/// A copy of `session` standing as `status` says, read back the way
/// storage reads it.
fn copy_session(session: &OrgSession, status: SessionStatus) -> Result<OrgSession, DomainError> {
    let progress = session.progress();
    OrgSession::reconstitute(OrgSessionRow {
        id: *session.id(),
        org_user_id: *session.org_user_id(),
        organization_id: *session.organization_id(),
        place: session.place(),
        refresh_token_hash: session.refresh_token_hash().clone(),
        progress: SignInProgressRow {
            method: progress.method(),
            factor: progress.factor(),
            owed: progress.owed(),
        },
        ip_address: session.ip_address().cloned(),
        user_agent: session.user_agent().cloned(),
        status,
        created_at: session.created_at(),
        last_active_at: session.last_active_at(),
        expires_at: session.expires_at(),
        kept_through: session.kept_through(),
    })
}

/// A copy of `session` as it stands.
fn copy_as_stored(session: &OrgSession) -> Result<OrgSession, DomainError> {
    copy_session(session, session.status())
}

/// In-memory organization session store that also records what was
/// revoked.
///
/// Keeps every session it holds or is handed, so a test reads back what a
/// use case saved, and records which sessions and members were signed out,
/// so a test shows that a use case which takes away a member's standing
/// also retired the sessions carrying it.
#[derive(Default)]
pub struct RecordingOrgSessionStore {
    sessions: Mutex<Vec<OrgSession>>,
    revoked_sessions: Mutex<Vec<SessionId>>,
    revoked_users: Mutex<Vec<OrgUserId>>,
    revocation: Revocation,
}

impl RecordingOrgSessionStore {
    /// A store with no session and nothing revoked.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store holding `sessions`.
    #[must_use]
    pub fn holding(sessions: impl IntoIterator<Item = OrgSession>) -> Self {
        let store = Self::default();
        store.sessions.lock().unwrap().extend(sessions);
        store
    }

    /// Every session held, in the order it was first saved.
    ///
    /// # Panics
    ///
    /// Panics if a held session no longer reads back as a consistent row.
    #[must_use]
    pub fn saved(&self) -> Vec<OrgSession> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .map(|session| copy_as_stored(session).expect("a held session reads back"))
            .collect()
    }

    /// How many sessions are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Whether every session of `org_user_id` was revoked at once.
    #[must_use]
    pub fn revoked(&self, org_user_id: &OrgUserId) -> bool {
        self.revoked_users.lock().unwrap().contains(org_user_id)
    }

    /// Whether the session `session_id` was revoked by its id.
    #[must_use]
    pub fn revoked_session(&self, session_id: &SessionId) -> bool {
        self.revoked_sessions.lock().unwrap().contains(session_id)
    }

    fn first(
        &self,
        matches: impl Fn(&OrgSession) -> bool,
    ) -> Result<Option<OrgSession>, DomainError> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .find(|session| matches(session))
            .map(copy_as_stored)
            .transpose()
    }

    fn revoke_where(&self, matches: impl Fn(&OrgSession) -> bool) -> Result<u64, DomainError> {
        let mut sessions = self.sessions.lock().unwrap();
        let mut count = 0;
        for session in sessions
            .iter_mut()
            .filter(|session| session.status() != SessionStatus::Revoked && matches(session))
        {
            *session = copy_session(session, SessionStatus::Revoked)?;
            count += 1;
        }
        Ok(count)
    }
}

impl RevocationSwitch for RecordingOrgSessionStore {
    fn revocation_mut(&mut self) -> &mut Revocation {
        &mut self.revocation
    }
}

#[async_trait]
impl OrgSessionStore for RecordingOrgSessionStore {
    async fn find_by_id(&self, id: &SessionId) -> Result<Option<OrgSession>, DomainError> {
        self.first(|session| session.id() == id)
    }

    async fn find_by_refresh_token_hash(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<OrgSession>, DomainError> {
        self.first(|session| session.refresh_token_hash() == hash)
    }

    async fn save(&self, session: &OrgSession) -> Result<(), DomainError> {
        let copy = copy_as_stored(session)?;
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.iter_mut().find(|held| held.id() == session.id()) {
            Some(held) => *held = copy,
            None => sessions.push(copy),
        }
        Ok(())
    }

    async fn list_active(
        &self,
        organization_id: &OrganizationId,
        sort: &SortOrder<OrgSessionSortField>,
        request: &PageRequest,
    ) -> Result<Page<OrgSession>, DomainError> {
        let active = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|session| session.organization_id() == organization_id && session.is_valid())
            .map(copy_as_stored)
            .collect::<Result<Vec<_>, _>>()?;
        page(active, sort, request)
    }

    async fn list_active_by_member(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgSession>, DomainError> {
        let mut own = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|session| session.org_user_id() == org_user_id && session.is_valid())
            .map(copy_as_stored)
            .collect::<Result<Vec<_>, _>>()?;
        own.sort_by_key(|session| std::cmp::Reverse(session.created_at()));
        Ok(own)
    }

    async fn revoke_by_id(&self, session_id: &SessionId) -> Result<bool, DomainError> {
        self.revoked_sessions.lock().unwrap().push(*session_id);
        Ok(self.revoke_where(|session| session.id() == session_id)? > 0)
    }

    async fn revoke_all_by_user(&self, org_user_id: &OrgUserId) -> Result<u64, DomainError> {
        if self.revocation == Revocation::Fails {
            return Err(DomainError::infra_msg("the session store is down"));
        }
        self.revoked_users.lock().unwrap().push(*org_user_id);
        self.revoke_where(|session| session.org_user_id() == org_user_id)
    }

    async fn revoke_all_by_org(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<u64, DomainError> {
        self.revoke_where(|session| session.organization_id() == organization_id)
    }

    async fn purge_expired(&self, retention_days: u32) -> Result<u64, DomainError> {
        let cutoff = clock::now() - Duration::days(i64::from(retention_days));
        let mut sessions = self.sessions.lock().unwrap();
        let before = sessions.len();
        sessions.retain(|session| session.is_valid() || session.expires_at() >= cutoff);
        Ok((before - sessions.len()) as u64)
    }
}

impl Fake for Arc<dyn OrgSessionStore> {
    fn fake() -> Self {
        Arc::new(RecordingOrgSessionStore::new())
    }
}
