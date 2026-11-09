//! A tenant's sessions, and the check the gateway makes on every request
//! carrying an app session: the store of `ports/shared/sessions.rs` and the
//! session check of `ports/authentication/app_sign_in.rs`, sharing one
//! mapping of the `sessions` table.
//!
//! A refresh retires the session it used and keeps the one carrying it on
//! in one statement, so of two refreshes presenting one token only one gets
//! a new session. Whether an app session is live is the domain's call on
//! the stored session; the check only records the use, at most once every
//! few seconds, so a busy session is not a write per request.

mod record;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::{AppSessionCheck, AppSessionClaim};
use ianua_app::ports::shared::SessionStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SessionId, TenantId, TokenHash, UserId};
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use self::record::{SessionColumns, SessionRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a refresh token to one session of a tenant.
const REFRESH_TOKEN_KEY: &str = "sessions_refresh_token_key";

/// How stale a session's last recorded use may be before a check records a
/// new one: often enough for the shortest idle timeout a tenant can set.
const TOUCH_EVERY: Duration = Duration::seconds(15);

/// The Postgres store of a tenant's sessions.
pub struct PgSessionStore {
    databases: Arc<Databases>,
}

impl PgSessionStore {
    /// A store keeping sessions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSessionStore {}

/// The Postgres check that an app session cookie still names a live
/// session.
pub struct PgAppSessionCheck {
    databases: Arc<Databases>,
}

impl PgAppSessionCheck {
    /// A check reading sessions from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgAppSessionCheck {}

/// The records of the sessions of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<SessionRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        SessionRecord,
        "queries/sessions/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

/// The session `id` of `tenant`, if it is kept.
async fn session_of(
    databases: &Databases,
    tenant: &ScopedTenant,
    id: &SessionId,
) -> Result<Option<Session<ResolvedTenant>>, DomainError> {
    let ids = [*id.as_uuid()];
    let records = scoped(databases, RowScope::from(tenant), async |connection| {
        records_of(connection, tenant, &ids).await
    })
    .await?;
    records
        .into_iter()
        .next()
        .map(SessionRecord::into_session)
        .transpose()
}

/// The sessions `records` hold, each rebuilt through the domain's checks.
fn sessions_from(records: Vec<SessionRecord>) -> Result<Vec<Session<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(SessionRecord::into_session)
        .collect()
}

/// Writes `session` of `tenant`, or finds its refresh token taken.
async fn write(
    connection: &mut PgConnection,
    tenant: &TenantId,
    session: &Session<ResolvedTenant>,
) -> Result<Uniqueness, sqlx::Error> {
    let columns = SessionColumns::of(session);
    let attempt = insert(connection, tenant, &columns).await;
    unique_on(attempt, REFRESH_TOKEN_KEY)
}

/// Inserts the row `columns` hold for `tenant`.
async fn insert(
    connection: &mut PgConnection,
    tenant: &TenantId,
    columns: &SessionColumns<'_>,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query_file!(
        "queries/sessions/save.sql",
        columns.id,
        tenant.as_uuid(),
        columns.user_id,
        columns.refresh_token_hash,
        columns.parent_id,
        columns.ip_address,
        columns.user_agent,
        columns.auth_method,
        columns.factor,
        columns.owed,
        columns.status,
        columns.app_service_id,
        columns.signed_in_at,
        columns.created_at,
        columns.last_active_at,
        columns.expires_at,
        columns.kept_through,
        columns.signed_in_from,
        columns.last_used_network,
        columns.last_used_latitude,
        columns.last_used_longitude,
        columns.last_used_country,
        columns.last_used_at,
    )
    .execute(connection)
    .await
}

/// Retires `parent` of `tenant` and keeps `child`, while the stored parent
/// is not revoked; answers whether it was.
/// The checked atomic rotation keeps all parent and child binds visible in SQL order.
#[allow(clippy::too_many_lines)]
async fn swap(
    connection: &mut PgConnection,
    tenant: &TenantId,
    parent: &SessionColumns<'_>,
    child: &SessionColumns<'_>,
) -> Result<bool, sqlx::Error> {
    let kept = sqlx::query_file!(
        "queries/sessions/rotate.sql",
        tenant.as_uuid(),
        parent.id,
        parent.status,
        parent.factor,
        parent.owed,
        parent.last_active_at,
        parent.kept_through,
        child.id,
        child.user_id,
        child.refresh_token_hash,
        child.parent_id,
        child.ip_address,
        child.user_agent,
        child.auth_method,
        child.factor,
        child.owed,
        child.status,
        child.app_service_id,
        child.signed_in_at,
        child.created_at,
        child.last_active_at,
        child.expires_at,
        child.kept_through,
        child.signed_in_from,
        child.last_used_network,
        child.last_used_latitude,
        child.last_used_longitude,
        child.last_used_country,
        child.last_used_at,
    )
    .execute(connection)
    .await?;
    Ok(kept.rows_affected() > 0)
}

/// Writes where `session` of `tenant` was last used, while it is active.
async fn write_last_use(
    connection: &mut PgConnection,
    tenant: &TenantId,
    session: &Session<ResolvedTenant>,
) -> Result<(), sqlx::Error> {
    let columns = SessionColumns::of(session);
    sqlx::query_file!(
        "queries/sessions/keep_last_use.sql",
        tenant.as_uuid(),
        columns.id,
        columns.last_used_network,
        columns.last_used_latitude,
        columns.last_used_longitude,
        columns.last_used_country,
        columns.last_used_at,
    )
    .execute(connection)
    .await
    .map(|_| ())
}

/// Writes `session`'s stopped status, while the stored one is active;
/// answers whether a row changed.
async fn write_stopped(
    connection: &mut PgConnection,
    tenant: &TenantId,
    session: &Session<ResolvedTenant>,
) -> Result<bool, sqlx::Error> {
    let columns = SessionColumns::of(session);
    let written = sqlx::query_file!(
        "queries/sessions/stop_if_active.sql",
        tenant.as_uuid(),
        columns.id,
        columns.status,
    )
    .execute(connection)
    .await?;
    Ok(written.rows_affected() > 0)
}

/// Whether `session` is one `claim` may be answered with at `now`: usable,
/// held by the person the claim names, opened by the claim's service, and
/// used within the idle timeout it was minted with.
fn admits(session: &Session<ResolvedTenant>, claim: &AppSessionClaim, now: OffsetDateTime) -> bool {
    session.is_usable(now)
        && session.user_id() == &claim.user_id
        && session.channel().app_service() == Some(&claim.service_id)
        && !idled(session.last_active_at(), claim.idle_timeout, now)
}

/// Whether a session last used at `last_active_at` went unused for longer
/// than `idle_timeout` by `now`. A session without one never idles out.
fn idled(
    last_active_at: OffsetDateTime,
    idle_timeout: Option<StdDuration>,
    now: OffsetDateTime,
) -> bool {
    idle_timeout.is_some_and(|idle| clock::between(last_active_at, now) >= idle)
}

/// When `session`, as it was read, stops counting: its absolute end or, if
/// sooner, the moment its idle timeout runs out from its last use. Later use
/// moves the second, so a cache that reaches it asks the store again rather
/// than ending a session still in use.
fn counts_until(
    session: &Session<ResolvedTenant>,
    idle_timeout: Option<StdDuration>,
) -> OffsetDateTime {
    let Some(idle) = idle_timeout else {
        return session.expires_at();
    };
    let idle = Duration::try_from(idle).unwrap_or(Duration::MAX);
    session
        .last_active_at()
        .saturating_add(idle)
        .min(session.expires_at())
}

#[async_trait]
impl SessionStore for PgSessionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SessionId,
    ) -> Result<Option<Session<ResolvedTenant>>, DomainError> {
        session_of(&self.databases, tenant_id, id).await
    }

    async fn find_by_refresh_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        hash: &TokenHash,
    ) -> Result<Option<Session<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SessionRecord,
                    "queries/sessions/by_refresh_token_hash.sql",
                    tenant_id.as_uuid(),
                    hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(SessionRecord::into_session).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write(connection, tenant_id, session).await,
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-session-of-the-tenant-holds",
                "another session of the tenant holds this refresh token"
            ))),
        }
    }

    async fn keep_last_use(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_last_use(connection, tenant_id, session).await,
        )
        .await
    }

    async fn stop_if_active(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_stopped(connection, tenant_id, session).await,
        )
        .await
    }

    async fn rotate(
        &self,
        tenant_id: &ScopedTenant,
        parent: &Session<ResolvedTenant>,
        child: &Session<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let (parent, child) = (SessionColumns::of(parent), SessionColumns::of(child));
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| swap(connection, tenant_id, &parent, &child).await,
        )
        .await
    }

    async fn was_rotated(
        &self,
        tenant_id: &ScopedTenant,
        id: &SessionId,
    ) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/sessions/rotated.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }

    async fn list_active_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Session<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SessionRecord,
                    "queries/sessions/active_of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        sessions_from(records)
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Session<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SessionRecord,
                    "queries/sessions/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        sessions_from(records)
    }

    async fn purge_ended(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let done = sqlx::query_file!(
                    "queries/sessions/purge_ended.sql",
                    tenant_id.as_uuid(),
                    cutoff
                )
                .execute(connection)
                .await?;
                Ok(done.rows_affected())
            },
        )
        .await
    }

    async fn revoke_all_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<u64, DomainError> {
        let revoked = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/sessions/revoke_of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(revoked.rows_affected())
    }

    async fn revoke_all_by_tenant(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        let revoked = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!("queries/sessions/revoke_of_tenant.sql", tenant_id.as_uuid())
                    .execute(connection)
                    .await
            },
        )
        .await?;
        Ok(revoked.rows_affected())
    }
}

#[async_trait]
impl AppSessionCheck for PgAppSessionCheck {
    async fn live_until(
        &self,
        tenant_id: &ScopedTenant,
        claim: &AppSessionClaim,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        let now = clock::now();
        let Some(session) = session_of(&self.databases, tenant_id, &claim.session_id).await? else {
            return Ok(None);
        };
        if !admits(&session, claim, now) {
            return Ok(None);
        }
        let stale_before = now.saturating_sub(TOUCH_EVERY);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/sessions/touch.sql",
                    tenant_id.as_uuid(),
                    claim.session_id.as_uuid(),
                    now,
                    stale_before
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(Some(counts_until(&session, claim.idle_timeout)))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::routing::ServiceStore;
    use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
    use ianua_domain::domains::authentication::sessions::last_use::{
        CallerNetwork, ObservedUse, WayBack,
    };
    use ianua_domain::domains::authentication::sessions::session::{SessionOrigin, SessionRow};
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::routing::service::Service;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{CountryCode, EventLabel, Fact, ServiceId};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::postgres::routing::PgServiceStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authentication::{app_session_row, hash, session_row};
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::{from_now, user_row};
    use crate::test_support::rows::routing::service_row;

    struct Fixture {
        db: TestDb,
        store: PgSessionStore,
        acme: ScopedTenant,
        ann: UserId,
        bob: UserId,
    }

    /// A fresh database holding Ann and Bob in Acme, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let user = User::reconstitute(user_row(email)).unwrap();
            users.save(&acme, &user).await.unwrap();
            ids.push(*user.id());
        }
        Fixture {
            store: PgSessionStore::new(Arc::clone(&db.databases)),
            db,
            acme,
            ann: ids[0],
            bob: ids[1],
        }
    }

    fn session(row: SessionRow) -> Session<ResolvedTenant> {
        Session::reconstitute(row).unwrap()
    }

    impl Fixture {
        async fn saved(&self, row: SessionRow) -> Session<ResolvedTenant> {
            let kept = session(row);
            self.store.save(&self.acme, &kept).await.unwrap();
            kept
        }

        async fn service(&self) -> ServiceId {
            let shop = Service::reconstitute(service_row("shop")).unwrap();
            PgServiceStore::new(Arc::clone(&self.db.databases))
                .save(&self.acme, &shop)
                .await
                .unwrap();
            *shop.id()
        }

        fn check(&self) -> PgAppSessionCheck {
            PgAppSessionCheck::new(Arc::clone(&self.db.databases))
        }
    }

    fn claim_on(session: &Session<ResolvedTenant>, service_id: ServiceId) -> AppSessionClaim {
        AppSessionClaim {
            session_id: *session.id(),
            user_id: *session.user_id(),
            service_id,
            idle_timeout: None,
            signed_in_from: session.signed_in_from(),
        }
    }

    /// Rebuilds a revoked parent with the caller's original sign-in timing.
    fn retired_session(
        parent: &Session<ResolvedTenant>,
        row: SessionRow,
    ) -> Session<ResolvedTenant> {
        session(SessionRow {
            id: *parent.id(),
            status: SessionStatus::Revoked,
            ..row
        })
    }

    /// Rebuilds a refresh child pointing at the supplied parent session.
    fn refresh_child(parent: &Session<ResolvedTenant>, row: SessionRow) -> Session<ResolvedTenant> {
        session(SessionRow {
            parent_id: SessionOrigin::RotatedFrom(*parent.id()),
            ..row
        })
    }

    /// Places all initial sign-in timestamps ten seconds before the fixture clock.
    fn recent_sign_in(user: UserId, refresh: &str) -> SessionRow {
        SessionRow {
            signed_in_at: from_now(-10),
            created_at: from_now(-10),
            last_active_at: from_now(-10),
            ..session_row(user, refresh)
        }
    }

    /// Ann's session is found by its id and by its refresh token, as it was
    /// saved.
    #[tokio::test]
    async fn a_saved_session_is_found_by_id_and_by_refresh_token() {
        let f = fixture().await;
        let kept = f.saved(session_row(f.ann, "refresh-1")).await;

        let by_id = f
            .store
            .find_by_id(&f.acme, kept.id())
            .await
            .unwrap()
            .unwrap();
        let by_token = f
            .store
            .find_by_refresh_token_hash(&f.acme, &hash("refresh-1"))
            .await
            .unwrap()
            .unwrap();

        for found in [&by_id, &by_token] {
            assert_eq!(found.id(), kept.id());
            assert_eq!(found.user_id(), kept.user_id());
            assert_eq!(found.owed(), kept.owed());
            assert_eq!(found.expires_at(), kept.expires_at());
            assert_eq!(found.channel(), kept.channel());
        }
    }

    /// A use of Ann's session from Berlin, seen now.
    fn observed_in_berlin() -> ObservedUse {
        ObservedUse {
            network: CallerNetwork::new("198.18.0.7").unwrap(),
            place: Fact::Known(
                IpGeolocation::new(52.52, 13.405, CountryCode::new("DE").unwrap(), None).unwrap(),
            ),
        }
    }

    /// Where Ann's session was last used is kept and comes back with it.
    #[tokio::test]
    async fn a_last_use_is_kept_and_read_back() {
        let f = fixture().await;
        let kept = f.saved(session_row(f.ann, "refresh-1")).await;
        let mut read = f
            .store
            .find_by_id(&f.acme, kept.id())
            .await
            .unwrap()
            .unwrap();
        read.note_use(observed_in_berlin(), clock::now());

        f.store.keep_last_use(&f.acme, &read).await.unwrap();

        let found = f
            .store
            .find_by_id(&f.acme, kept.id())
            .await
            .unwrap()
            .unwrap();
        let held = found.last_use();
        let last = held.known().unwrap();
        assert_eq!(last.network().as_str(), "198.18.0.7");
        assert_eq!(last.place().country_code().as_str(), "DE");
    }

    /// Ann's session was frozen a moment ago. A write of where it was last
    /// used, read before the freeze, leaves the status as it is.
    #[tokio::test]
    async fn a_kept_last_use_does_not_touch_a_stopped_session() {
        let f = fixture().await;
        let kept = f.saved(session_row(f.ann, "refresh-1")).await;
        let mut read = f
            .store
            .find_by_id(&f.acme, kept.id())
            .await
            .unwrap()
            .unwrap();
        read.note_use(observed_in_berlin(), clock::now());
        f.saved(SessionRow {
            id: *kept.id(),
            status: SessionStatus::Suspended,
            ..session_row(f.ann, "refresh-1")
        })
        .await;

        f.store.keep_last_use(&f.acme, &read).await.unwrap();

        let found = f
            .store
            .find_by_id(&f.acme, kept.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), SessionStatus::Suspended);
        assert!(found.last_use().known().is_none());
    }

    /// Two requests race to freeze Ann's session. Only the first is told
    /// it changed the row, so only that one records the event.
    #[tokio::test]
    async fn only_one_request_stops_a_session() {
        let f = fixture().await;
        let kept = f.saved(session_row(f.ann, "refresh-1")).await;
        let mut frozen = f
            .store
            .find_by_id(&f.acme, kept.id())
            .await
            .unwrap()
            .unwrap();
        frozen
            .stop_taken_over(WayBack::OwnFactor, EventLabel::of("Ann"))
            .unwrap();

        let first = f.store.stop_if_active(&f.acme, &frozen).await.unwrap();
        let second = f.store.stop_if_active(&f.acme, &frozen).await.unwrap();

        assert!(first);
        assert!(!second);
        let found = f
            .store
            .find_by_id(&f.acme, kept.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), SessionStatus::Suspended);
    }

    /// An id or token nobody holds finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_session_is_not_found() {
        let f = fixture().await;

        assert!(
            f.store
                .find_by_id(&f.acme, &SessionId::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            f.store
                .find_by_refresh_token_hash(&f.acme, &hash("nobody"))
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Ann's session is suspended: saving it again keeps the new status.
    #[tokio::test]
    async fn saving_again_keeps_the_new_status() {
        let f = fixture().await;
        let kept = f.saved(session_row(f.ann, "refresh-1")).await;

        f.saved(SessionRow {
            id: *kept.id(),
            status: SessionStatus::Suspended,
            ..session_row(f.ann, "refresh-1")
        })
        .await;

        let found = f
            .store
            .find_by_id(&f.acme, kept.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), SessionStatus::Suspended);
    }

    /// Saving a stale session after all of Ann's sessions are revoked
    /// succeeds without undoing its revocation.
    #[tokio::test]
    async fn a_save_never_brings_a_revoked_session_back() {
        let f = fixture().await;
        let stale = f.saved(session_row(f.ann, "refresh-1")).await;
        f.store.revoke_all_by_user(&f.acme, &f.ann).await.unwrap();

        f.store.save(&f.acme, &stale).await.unwrap();

        let found = f
            .store
            .find_by_id(&f.acme, stale.id())
            .await
            .unwrap()
            .unwrap();
        assert!(found.is_revoked());
    }

    /// Saving Bob's session with Ann's existing refresh token returns a
    /// conflict within their tenant.
    #[tokio::test]
    async fn a_refresh_token_another_session_holds_is_refused() {
        let f = fixture().await;
        f.saved(session_row(f.ann, "refresh-1")).await;

        let second = f
            .store
            .save(&f.acme, &session(session_row(f.bob, "refresh-1")))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// A session rotates once: the parent becomes revoked and rotated,
    /// and a second rotation is refused without saving its child.
    #[tokio::test]
    async fn a_session_is_rotated_once() {
        let f = fixture().await;
        let parent = f.saved(session_row(f.ann, "refresh-1")).await;
        let retired = retired_session(&parent, session_row(f.ann, "refresh-1"));
        let child = refresh_child(&parent, session_row(f.ann, "refresh-2"));
        let late = refresh_child(&parent, session_row(f.ann, "refresh-3"));

        let first = f.store.rotate(&f.acme, &retired, &child).await.unwrap();
        let second = f.store.rotate(&f.acme, &retired, &late).await.unwrap();

        assert!(first);
        assert!(!second);
        assert!(f.store.was_rotated(&f.acme, parent.id()).await.unwrap());
        assert!(!f.store.was_rotated(&f.acme, child.id()).await.unwrap());
        assert!(
            f.store
                .find_by_id(&f.acme, late.id())
                .await
                .unwrap()
                .is_none()
        );
        let stored = f
            .store
            .find_by_id(&f.acme, parent.id())
            .await
            .unwrap()
            .unwrap();
        assert!(stored.is_revoked());
    }

    /// Ann's sessions still standing are listed newest first; a revoked one
    /// and Bob's are not.
    #[tokio::test]
    async fn the_sessions_a_user_holds_are_listed_newest_first() {
        let f = fixture().await;
        let older = f.saved(session_row(f.ann, "refresh-1")).await;
        let newer = f
            .saved(SessionRow {
                signed_in_at: from_now(-10),
                created_at: from_now(-10),
                last_active_at: from_now(-10),
                ..session_row(f.ann, "refresh-2")
            })
            .await;
        f.saved(SessionRow {
            status: SessionStatus::Revoked,
            ..session_row(f.ann, "refresh-3")
        })
        .await;
        f.saved(session_row(f.bob, "refresh-4")).await;

        let listed = f.store.list_active_by_user(&f.acme, &f.ann).await.unwrap();

        let ids: Vec<&SessionId> = listed.iter().map(Session::id).collect();
        assert_eq!(ids, [newer.id(), older.id()]);
    }

    /// Ann's sign-in list contains her live refresh child and ended
    /// session, newest first, without the replaced parent or Bob's session.
    #[tokio::test]
    async fn every_sign_in_of_a_user_is_listed_once_ended_or_open() {
        let f = fixture().await;
        let ended = f
            .saved(SessionRow {
                status: SessionStatus::Revoked,
                ..session_row(f.ann, "refresh-1")
            })
            .await;
        let parent = f.saved(recent_sign_in(f.ann, "refresh-2")).await;
        let retired = retired_session(&parent, recent_sign_in(f.ann, "refresh-2"));
        let child = refresh_child(
            &parent,
            SessionRow {
                signed_in_at: from_now(-10),
                created_at: from_now(-5),
                last_active_at: from_now(-5),
                ..session_row(f.ann, "refresh-3")
            },
        );
        f.store.rotate(&f.acme, &retired, &child).await.unwrap();
        f.saved(session_row(f.bob, "refresh-4")).await;

        let listed = f.store.list_by_user(&f.acme, &f.ann).await.unwrap();

        let ids: Vec<&SessionId> = listed.iter().map(Session::id).collect();
        assert_eq!(ids, [child.id(), ended.id()]);
    }

    /// Purging removes sessions expired or revoked before the cutoff,
    /// preserving live sessions, recent revocations and live refresh
    /// ancestry. A purge in another tenant removes nothing.
    #[tokio::test]
    async fn only_sessions_over_before_the_cutoff_are_purged() {
        let f = fixture().await;
        let old = from_now(-1_000);
        let cutoff = from_now(-500);
        let [ran_out, ended, parent] = ended_sessions(&f, old).await;
        let [parent, child, in_force, ended_since] = retained_sessions(&f, old, parent).await;

        let purged = f.store.purge_ended(&f.acme, cutoff).await.unwrap();
        let elsewhere = f.store.purge_ended(&tenant(), from_now(0)).await.unwrap();

        assert_eq!(purged, 2);
        assert_eq!(elsewhere, 0);
        for gone in [&ran_out, &ended] {
            assert!(
                f.store
                    .find_by_id(&f.acme, gone.id())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        for kept in [&parent, &child, &in_force, &ended_since] {
            assert!(
                f.store
                    .find_by_id(&f.acme, kept.id())
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }

    /// Saves expired and revoked sessions, including the future refresh parent.
    async fn ended_sessions(f: &Fixture, old: OffsetDateTime) -> [Session<ResolvedTenant>; 3] {
        let over = |refresh: &str, status: SessionStatus, expires_at| SessionRow {
            status,
            signed_in_at: old,
            created_at: old,
            last_active_at: old,
            expires_at,
            ..session_row(f.ann, refresh)
        };
        let ran_out = f
            .saved(over("refresh-1", SessionStatus::Active, from_now(-900)))
            .await;
        let ended = f
            .saved(over("refresh-2", SessionStatus::Revoked, from_now(60)))
            .await;
        let parent = f
            .saved(over("refresh-3", SessionStatus::Revoked, from_now(60)))
            .await;
        [ran_out, ended, parent]
    }

    /// Saves the live child and sessions that must survive the retention cutoff.
    async fn retained_sessions(
        f: &Fixture,
        old: OffsetDateTime,
        parent: Session<ResolvedTenant>,
    ) -> [Session<ResolvedTenant>; 4] {
        let child = f
            .saved(SessionRow {
                parent_id: SessionOrigin::RotatedFrom(*parent.id()),
                ..session_row(f.ann, "refresh-4")
            })
            .await;
        let in_force = f
            .saved(SessionRow {
                signed_in_at: old,
                created_at: old,
                last_active_at: old,
                ..session_row(f.ann, "refresh-5")
            })
            .await;
        let ended_since = f
            .saved(SessionRow {
                status: SessionStatus::Revoked,
                ..session_row(f.ann, "refresh-6")
            })
            .await;

        [parent, child, in_force, ended_since]
    }

    /// Revoking Ann's sessions ends both of hers and counts them; Bob's
    /// stands until the whole tenant is revoked, which counts only his.
    #[tokio::test]
    async fn revoking_counts_the_sessions_it_ended() {
        let f = fixture().await;
        f.saved(session_row(f.ann, "refresh-1")).await;
        f.saved(session_row(f.ann, "refresh-2")).await;
        f.saved(session_row(f.bob, "refresh-3")).await;

        let of_ann = f.store.revoke_all_by_user(&f.acme, &f.ann).await.unwrap();
        let bob_left = f.store.list_active_by_user(&f.acme, &f.bob).await.unwrap();
        let of_tenant = f.store.revoke_all_by_tenant(&f.acme).await.unwrap();

        assert_eq!(of_ann, 2);
        assert_eq!(bob_left.len(), 1);
        assert_eq!(of_tenant, 1);
        assert!(
            f.store
                .list_active_by_user(&f.acme, &f.ann)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Globex cannot find Acme's session by id or refresh token, and its
    /// tenant-wide revocation counts no sessions.
    #[tokio::test]
    async fn another_tenants_sessions_are_invisible() {
        let f = fixture().await;
        let kept = f.saved(session_row(f.ann, "refresh-1")).await;
        let globex = tenant();

        let by_id = f.store.find_by_id(&globex, kept.id()).await.unwrap();
        let by_token = f
            .store
            .find_by_refresh_token_hash(&globex, &hash("refresh-1"))
            .await
            .unwrap();
        let revoked = f.store.revoke_all_by_tenant(&globex).await.unwrap();

        assert!(by_id.is_none());
        assert!(by_token.is_none());
        assert_eq!(revoked, 0);
    }

    /// An invalid IP address in a stored session makes its read fail as
    /// corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_session_is_refused() {
        let f = fixture().await;
        let kept = f.saved(session_row(f.ann, "refresh-1")).await;
        f.db.tamper("UPDATE sessions SET ip_address = 'not an address'")
            .await;

        let read = f.store.find_by_id(&f.acme, kept.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Ann's session opened on the shop is live for the shop, and the check
    /// records her use of it.
    #[tokio::test]
    async fn an_app_session_is_live_for_its_own_service_and_records_its_use() {
        let f = fixture().await;
        let shop = f.service().await;
        let kept = f.saved(app_session_row(f.ann, shop, "refresh-1")).await;

        let live = f
            .check()
            .is_live(&f.acme, &claim_on(&kept, shop))
            .await
            .unwrap();

        let found = f
            .store
            .find_by_id(&f.acme, kept.id())
            .await
            .unwrap()
            .unwrap();
        assert!(live);
        assert!(found.last_active_at() > kept.last_active_at());
    }

    /// The app-session check refuses a different service, a revoked
    /// session and a session beyond its idle timeout.
    #[tokio::test]
    async fn an_app_session_on_another_service_ended_or_idle_is_not_live() {
        let f = fixture().await;
        let shop = f.service().await;
        let kept = f.saved(app_session_row(f.ann, shop, "refresh-1")).await;
        let ended = f
            .saved(SessionRow {
                status: SessionStatus::Revoked,
                ..app_session_row(f.ann, shop, "refresh-2")
            })
            .await;
        let idle = AppSessionClaim {
            idle_timeout: Some(StdDuration::from_secs(30)),
            ..claim_on(&kept, shop)
        };

        let elsewhere = f
            .check()
            .is_live(&f.acme, &claim_on(&kept, ServiceId::new()))
            .await
            .unwrap();
        let after_end = f
            .check()
            .is_live(&f.acme, &claim_on(&ended, shop))
            .await
            .unwrap();
        let after_idle = f.check().is_live(&f.acme, &idle).await.unwrap();

        assert!(!elsewhere);
        assert!(!after_end);
        assert!(!after_idle);
    }

    /// Ann's app session counts until its absolute end when no idle timeout
    /// comes first; with a timeout shorter than the time left it counts
    /// until that timeout runs out from her last use.
    #[tokio::test]
    async fn an_app_session_counts_until_its_earliest_end() {
        let f = fixture().await;
        let shop = f.service().await;
        let kept = f.saved(app_session_row(f.ann, shop, "refresh-1")).await;
        let idle = StdDuration::from_secs(300);
        let with_idle = AppSessionClaim {
            idle_timeout: Some(idle),
            ..claim_on(&kept, shop)
        };

        let idling = f.check().live_until(&f.acme, &with_idle).await.unwrap();
        let plain = f
            .check()
            .live_until(&f.acme, &claim_on(&kept, shop))
            .await
            .unwrap();

        assert_eq!(
            idling,
            Some(kept.last_active_at().saturating_add(Duration::seconds(300)))
        );
        assert_eq!(plain, Some(kept.expires_at()));
    }

    /// Ann's app session counts a second before its end, and not at that
    /// very instant.
    #[tokio::test]
    async fn an_app_session_stops_counting_at_its_exact_end() {
        let f = fixture().await;
        let shop = f.service().await;
        let end = from_now(3600).replace_nanosecond(0).unwrap();
        let kept = f
            .saved(SessionRow {
                expires_at: end,
                ..app_session_row(f.ann, shop, "refresh-1")
            })
            .await;
        let claim = claim_on(&kept, shop);
        let frozen = clock::freeze(end - time::Duration::seconds(1));

        let before = f.check().live_until(&f.acme, &claim).await.unwrap();
        frozen.advance_to(end);
        let at_the_end = f.check().live_until(&f.acme, &claim).await.unwrap();

        assert_eq!(before, Some(end));
        assert_eq!(at_the_end, None);
    }

    /// The app-session check refuses both an unknown session id and a
    /// stored session looked up through another tenant.
    #[tokio::test]
    async fn a_missing_app_session_is_not_live() {
        let f = fixture().await;
        let shop = f.service().await;
        let kept = f.saved(app_session_row(f.ann, shop, "refresh-1")).await;
        let missing = AppSessionClaim {
            session_id: SessionId::new(),
            ..claim_on(&kept, shop)
        };

        let unknown = f.check().is_live(&f.acme, &missing).await.unwrap();
        let elsewhere = f
            .check()
            .is_live(&tenant(), &claim_on(&kept, shop))
            .await
            .unwrap();

        assert!(!unknown);
        assert!(!elsewhere);
    }
}
