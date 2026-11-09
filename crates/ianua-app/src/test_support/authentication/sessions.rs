//! Fakes for sessions.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::authentication::sessions::session::{
    Session, SessionOrigin, SessionRow,
};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CredentialChange, Fact, SessionId, TenantId, TokenHash, UserId};
use time::{Duration, OffsetDateTime};

use crate::ports::TenantScoped;
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::oauth::signed_in_session;
use crate::test_support::{Fake, ReadBeforeWrite, Revocation, test_ctx};

/// A session store whose bulk revocation a test can make fail.
pub trait RevocationSwitch: Sized {
    /// The switch the store's bulk revocation reads.
    fn revocation_mut(&mut self) -> &mut Revocation;

    /// The same store, failing every bulk revocation as if it were
    /// unreachable.
    #[must_use]
    fn failing_revocation(mut self) -> Self {
        *self.revocation_mut() = Revocation::Fails;
        self
    }
}

/// In-memory session store, keeping each session in its tenant as it was
/// last saved.
pub struct FakeSessionStore {
    sessions: Mutex<Vec<(TenantId, Session<ResolvedTenant>)>>,
    /// How many times `revoke_all_by_user` was called.
    pub revoke_all_count: Mutex<u32>,
    /// How many times `revoke_all_by_tenant` was called.
    pub revoke_all_by_tenant_count: Mutex<u32>,
    revocation: Revocation,
}

impl TenantScoped for FakeSessionStore {}

impl RevocationSwitch for FakeSessionStore {
    fn revocation_mut(&mut self) -> &mut Revocation {
        &mut self.revocation
    }
}

impl FakeSessionStore {
    /// No sessions.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
            revoke_all_count: Mutex::new(0),
            revoke_all_by_tenant_count: Mutex::new(0),
            revocation: Revocation::Succeeds,
        }
    }

    /// Holds `session` in the test tenant.
    #[must_use]
    pub fn with_session(session: Session<ResolvedTenant>) -> Self {
        Self::holding_in(test_ctx().tenant_id(), [session])
    }

    /// Holds `sessions` in `tenant_id`.
    #[must_use]
    pub fn holding_in(
        tenant_id: TenantId,
        sessions: impl IntoIterator<Item = Session<ResolvedTenant>>,
    ) -> Self {
        let store = Self::empty();
        store
            .sessions
            .lock()
            .unwrap()
            .extend(sessions.into_iter().map(|session| (tenant_id, session)));
        store
    }

    /// The status of the session `id`, in whichever tenant holds it.
    #[must_use]
    pub fn get_status(&self, id: &SessionId) -> Option<SessionStatus> {
        self.get_session(id).map(|session| session.status())
    }

    /// How many sessions are held, across tenants.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// A copy of the session `id`, in whichever tenant holds it.
    #[must_use]
    pub fn get_session(&self, id: &SessionId) -> Option<Session<ResolvedTenant>> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .find(|(_, session)| session.id() == id)
            .map(|(_, session)| clone_session(session))
    }

    fn find_in(
        &self,
        tenant_id: &ScopedTenant,
        matches: impl Fn(&Session<ResolvedTenant>) -> bool,
    ) -> Option<Session<ResolvedTenant>> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .find(|(held_in, session)| held_in == &**tenant_id && matches(session))
            .map(|(_, session)| clone_session(session))
    }

    fn revoke_where(
        &self,
        tenant_id: &ScopedTenant,
        matches: impl Fn(&Session<ResolvedTenant>) -> bool,
    ) -> Result<u64, DomainError> {
        if self.revocation == Revocation::Fails {
            return Err(DomainError::infra_msg("the session store is down"));
        }
        let mut sessions = self.sessions.lock().unwrap();
        let ending = sessions.iter_mut().filter(|(held_in, session)| {
            held_in == &**tenant_id && !session.is_revoked() && matches(session)
        });
        let mut revoked = 0;
        for (_, session) in ending {
            *session = revoked_copy(session);
            revoked += 1;
        }
        Ok(revoked)
    }
}

#[async_trait]
impl SessionStore for FakeSessionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SessionId,
    ) -> Result<Option<Session<ResolvedTenant>>, DomainError> {
        Ok(self.find_in(tenant_id, |session| session.id() == id))
    }

    async fn find_by_refresh_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        hash: &TokenHash,
    ) -> Result<Option<Session<ResolvedTenant>>, DomainError> {
        Ok(self.find_in(tenant_id, |session| session.refresh_token_hash() == hash))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|(held_in, held)| !(held_in == &**tenant_id && held.id() == session.id()));
        sessions.push((**tenant_id, clone_session(session)));
        Ok(())
    }

    async fn keep_last_use(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some((_, stored)) = sessions.iter_mut().find(|(held_in, held)| {
            held_in == &**tenant_id
                && held.id() == session.id()
                && held.status() == SessionStatus::Active
        }) {
            *stored = clone_session(session);
        }
        Ok(())
    }

    async fn stop_if_active(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let mut sessions = self.sessions.lock().unwrap();
        let Some((_, stored)) = sessions.iter_mut().find(|(held_in, held)| {
            held_in == &**tenant_id
                && held.id() == session.id()
                && held.status() == SessionStatus::Active
        }) else {
            return Ok(false);
        };
        *stored = clone_session(session);
        Ok(true)
    }

    async fn rotate(
        &self,
        tenant_id: &ScopedTenant,
        parent: &Session<ResolvedTenant>,
        child: &Session<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let mut sessions = self.sessions.lock().unwrap();
        let Some((_, stored)) = sessions.iter_mut().find(|(held_in, held)| {
            held_in == &**tenant_id && held.id() == parent.id() && !held.is_revoked()
        }) else {
            return Ok(false);
        };
        *stored = clone_session(parent);
        sessions.push((**tenant_id, clone_session(child)));
        Ok(true)
    }

    async fn was_rotated(
        &self,
        tenant_id: &ScopedTenant,
        id: &SessionId,
    ) -> Result<bool, DomainError> {
        Ok(self
            .find_in(tenant_id, |session| {
                session.parent_id().parent() == Some(id)
            })
            .is_some())
    }

    async fn list_active_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Session<ResolvedTenant>>, DomainError> {
        let mut held: Vec<_> = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|(held_in, session)| {
                held_in == &**tenant_id && session.user_id() == user_id && !session.is_revoked()
            })
            .map(|(_, session)| clone_session(session))
            .collect();
        held.reverse();
        Ok(held)
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Session<ResolvedTenant>>, DomainError> {
        let sessions = self.sessions.lock().unwrap();
        let replaced: Vec<SessionId> = sessions
            .iter()
            .filter(|(held_in, _)| held_in == &**tenant_id)
            .filter_map(|(_, session)| session.parent_id().parent().cloned())
            .collect();
        let mut held: Vec<_> = sessions
            .iter()
            .filter(|(held_in, session)| {
                held_in == &**tenant_id
                    && session.user_id() == user_id
                    && !replaced.contains(session.id())
            })
            .map(|(_, session)| clone_session(session))
            .collect();
        held.reverse();
        Ok(held)
    }

    async fn purge_ended(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let mut sessions = self.sessions.lock().unwrap();
        let replaced: Vec<SessionId> = sessions
            .iter()
            .filter(|(held_in, _)| held_in == &**tenant_id)
            .filter_map(|(_, session)| session.parent_id().parent().cloned())
            .collect();
        let over = |session: &Session<ResolvedTenant>| {
            session.expires_at() < cutoff
                || (session.is_revoked()
                    && session.last_active_at() < cutoff
                    && !replaced.contains(session.id()))
        };
        let before = sessions.len();
        sessions.retain(|(held_in, session)| !(held_in == &**tenant_id && over(session)));
        Ok(u64::try_from(before - sessions.len()).unwrap())
    }

    async fn revoke_all_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<u64, DomainError> {
        *self.revoke_all_count.lock().unwrap() += 1;
        self.revoke_where(tenant_id, |session| session.user_id() == user_id)
    }

    async fn revoke_all_by_tenant(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        *self.revoke_all_by_tenant_count.lock().unwrap() += 1;
        self.revoke_where(tenant_id, |_| true)
    }
}

/// `user_id`'s dashboard session, signed in by password a minute ago,
/// active and holding the refresh token whose hash is `refresh_hash`, still
/// owing `owed`. [`SecondFactor::NotOwed`] makes a finished sign-in.
///
/// # Panics
///
/// Never for what a password sign-in may owe: the row is consistent.
#[must_use]
pub fn password_session(
    user_id: UserId,
    refresh_hash: &str,
    owed: SecondFactor,
) -> Session<ResolvedTenant> {
    let now = clock::now();
    let started = now - Duration::minutes(1);
    Session::reconstitute(SessionRow {
        id: SessionId::new(),
        user_id,
        refresh_token_hash: TokenHash::from_stored(refresh_hash.to_owned()),
        parent_id: SessionOrigin::SignIn,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        signed_in_from: Fact::Unknown,
        progress: SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed,
        },
        status: SessionStatus::Active,
        channel: SessionChannel::Dashboard,
        signed_in_at: started,
        created_at: started,
        last_active_at: now,
        expires_at: now + Duration::hours(1),
        kept_through: CredentialChange::Never,
        last_use: Fact::Unknown,
    })
    .expect("a fresh password session is a consistent row")
}

/// A copy of `session`, which does not implement `Clone`, rebuilt from its
/// stored row the way a real store would read it back.
///
/// # Panics
///
/// Panics if the session's own fields no longer make a valid row, which a
/// session the domain built never does.
#[must_use]
pub fn clone_session(session: &Session<ResolvedTenant>) -> Session<ResolvedTenant> {
    Session::reconstitute(row_of(session)).expect("a live session's own row rebuilds")
}

/// The stored row of a fresh signed-in session of `user_id`, for a test
/// that shapes one of its own from it.
#[must_use]
pub fn session_row_for(user_id: UserId) -> SessionRow {
    row_of(&signed_in_session(SessionId::new(), user_id))
}

/// A copy of `session`, revoked as a bulk revocation in storage leaves it.
fn revoked_copy(session: &Session<ResolvedTenant>) -> Session<ResolvedTenant> {
    let row = SessionRow {
        status: SessionStatus::Revoked,
        ..row_of(session)
    };
    Session::reconstitute(row).expect("a live session's own row rebuilds")
}

/// The stored row of `session`.
fn row_of(session: &Session<ResolvedTenant>) -> SessionRow {
    SessionRow {
        id: *session.id(),
        user_id: *session.user_id(),
        refresh_token_hash: session.refresh_token_hash().clone(),
        parent_id: session.parent_id().clone(),
        ip_address: session.ip_address().cloned(),
        user_agent: session.user_agent().cloned(),
        signed_in_from: session.signed_in_from(),
        progress: SignInProgressRow {
            method: session.auth_method(),
            factor: session.mfa_method(),
            owed: session.owed(),
        },
        status: session.status(),
        channel: session.channel(),
        signed_in_at: session.signed_in_at(),
        created_at: session.created_at(),
        last_active_at: session.last_active_at(),
        expires_at: session.expires_at(),
        kept_through: session.kept_through(),
        last_use: session.last_use().cloned(),
    }
}

impl Fake for Arc<dyn SessionStore> {
    fn fake() -> Self {
        Arc::new(FakeSessionStore::empty())
    }
}

#[async_trait]
impl SessionStore for ReadBeforeWrite<FakeSessionStore> {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SessionId,
    ) -> Result<Option<Session<ResolvedTenant>>, DomainError> {
        self.seen.find_by_id(tenant_id, id).await
    }

    async fn find_by_refresh_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        hash: &TokenHash,
    ) -> Result<Option<Session<ResolvedTenant>>, DomainError> {
        self.seen.find_by_refresh_token_hash(tenant_id, hash).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.live.save(tenant_id, session).await
    }

    async fn keep_last_use(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.live.keep_last_use(tenant_id, session).await
    }

    async fn stop_if_active(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        self.live.stop_if_active(tenant_id, session).await
    }

    async fn rotate(
        &self,
        tenant_id: &ScopedTenant,
        parent: &Session<ResolvedTenant>,
        child: &Session<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        self.live.rotate(tenant_id, parent, child).await
    }

    async fn was_rotated(
        &self,
        tenant_id: &ScopedTenant,
        id: &SessionId,
    ) -> Result<bool, DomainError> {
        self.live.was_rotated(tenant_id, id).await
    }

    async fn list_active_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Session<ResolvedTenant>>, DomainError> {
        self.seen.list_active_by_user(tenant_id, user_id).await
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Session<ResolvedTenant>>, DomainError> {
        self.seen.list_by_user(tenant_id, user_id).await
    }

    async fn purge_ended(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        self.live.purge_ended(tenant_id, cutoff).await
    }

    async fn revoke_all_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<u64, DomainError> {
        self.live.revoke_all_by_user(tenant_id, user_id).await
    }

    async fn revoke_all_by_tenant(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        self.live.revoke_all_by_tenant(tenant_id).await
    }
}
