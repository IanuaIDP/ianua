//! Members' sessions on the management plane, kept in the platform
//! database.
//!
//! A session belongs to its organization and its member, never to a
//! tenant, so these are the platform's own rows. A list first reads the ids
//! of its page, then reads those rows through the one query by ids. A
//! revocation is one update, so a member signed out everywhere is signed
//! out at once.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::organization::{OrgSessionSortField, OrgSessionStore};
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId, SessionId, TokenHash};
use sqlx::PgConnection;
use time::Duration;
use uuid::Uuid;

use self::record::{SessionColumns, SessionRecord};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of members' sessions.
pub struct PgOrgSessionStore {
    databases: Arc<Databases>,
}

impl PgOrgSessionStore {
    /// A store keeping sessions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// How many sessions `change` revoked or deleted.
    async fn changed(
        &self,
        change: impl AsyncFnOnce(&mut PgConnection) -> Result<u64, sqlx::Error>,
    ) -> Result<u64, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, change).await
    }
}

/// The records of the sessions `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<SessionRecord>, sqlx::Error> {
    sqlx::query_file_as!(SessionRecord, "queries/org_sessions/by_ids.sql", ids)
        .fetch_all(connection)
        .await
}

fn rebuilt(records: Vec<SessionRecord>) -> Result<Vec<OrgSession>, DomainError> {
    records
        .into_iter()
        .map(SessionRecord::into_session)
        .collect()
}

impl SortColumns for OrgSessionSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::LastActiveAt => "last_active_at",
            Self::ExpiresAt => "expires_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The ids of the sessions of `organization_id` in force at `now`: active,
/// not expired, and owing nothing more to finish signing in.
fn in_force(organization_id: &OrganizationId) -> PageQuery<'static> {
    PageQuery::ids("id", "org_sessions")
        .filter("organization_id = ?", *organization_id.as_uuid())
        .keep("status = 'active'")
        .keep("owed = 'not_owed'")
        .filter("expires_at > ?", clock::now())
}

#[async_trait]
impl OrgSessionStore for PgOrgSessionStore {
    async fn find_by_id(&self, id: &SessionId) -> Result<Option<OrgSession>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            records_of(connection, &ids).await
        })
        .await?;
        records
            .into_iter()
            .next()
            .map(SessionRecord::into_session)
            .transpose()
    }

    async fn find_by_refresh_token_hash(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<OrgSession>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                SessionRecord,
                "queries/org_sessions/by_refresh_token_hash.sql",
                hash.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(SessionRecord::into_session).transpose()
    }

    async fn save(&self, session: &OrgSession) -> Result<(), DomainError> {
        let columns = SessionColumns::of(session);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_sessions/save.sql",
                columns.id,
                columns.organization_id,
                columns.org_user_id,
                columns.working_tenant,
                columns.refresh_token_hash,
                columns.auth_method,
                columns.factor,
                columns.owed,
                columns.ip_address,
                columns.user_agent,
                columns.status,
                columns.kept_through,
                columns.created_at,
                columns.last_active_at,
                columns.expires_at,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    async fn list_active(
        &self,
        organization_id: &OrganizationId,
        sort: &SortOrder<OrgSessionSortField>,
        page: &PageRequest,
    ) -> Result<Page<OrgSession>, DomainError> {
        let keyset = page.keyset(sort)?;
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids = in_force(organization_id)
                .fetch(&keyset, &mut *connection)
                .await?;
            let records = records_of(connection, &ids).await?;
            Ok(in_page_order(&ids, records, |record| record.id))
        })
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn list_active_by_member(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgSession>, DomainError> {
        let now = clock::now();
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                SessionRecord,
                "queries/org_sessions/in_force_of_member.sql",
                org_user_id.as_uuid(),
                now
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        rebuilt(records)
    }

    async fn revoke_by_id(&self, session_id: &SessionId) -> Result<bool, DomainError> {
        let revoked = self
            .changed(async |connection| {
                let done =
                    sqlx::query_file!("queries/org_sessions/revoke_one.sql", session_id.as_uuid())
                        .execute(connection)
                        .await?;
                Ok(done.rows_affected())
            })
            .await?;
        Ok(revoked > 0)
    }

    async fn revoke_all_by_user(&self, org_user_id: &OrgUserId) -> Result<u64, DomainError> {
        self.changed(async |connection| {
            let done = sqlx::query_file!(
                "queries/org_sessions/revoke_of_member.sql",
                org_user_id.as_uuid()
            )
            .execute(connection)
            .await?;
            Ok(done.rows_affected())
        })
        .await
    }

    async fn revoke_all_by_org(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<u64, DomainError> {
        self.changed(async |connection| {
            let done = sqlx::query_file!(
                "queries/org_sessions/revoke_in_organization.sql",
                organization_id.as_uuid()
            )
            .execute(connection)
            .await?;
            Ok(done.rows_affected())
        })
        .await
    }

    async fn purge_expired(&self, retention_days: u32) -> Result<u64, DomainError> {
        let cutoff = clock::now().saturating_sub(Duration::days(i64::from(retention_days)));
        self.changed(async |connection| {
            let done = sqlx::query_file!("queries/org_sessions/purge_expired.sql", cutoff)
                .execute(connection)
                .await?;
            Ok(done.rows_affected())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::organization::access::session::{OrgSessionRow, SessionPlace};
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{Fact, TenantId};

    use super::*;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{
        expired_org_session_row, org_session_row, org_user_row, organization_row,
    };
    use crate::test_support::rows::tenant::tenant_row;

    /// One organization as the tests arrange it: its id, a tenant of it, and
    /// two members.
    struct Held {
        organization: OrganizationId,
        tenant: TenantId,
        ann: OrgUserId,
        bob: OrgUserId,
    }

    struct Fixture {
        database: TestDb,
        store: PgOrgSessionStore,
        acme: Held,
        globex: Held,
    }

    /// A fresh database holding Acme and Globex, each with a tenant and two
    /// members, and the store on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let acme = an_organization(&database, "acme").await;
        let globex = an_organization(&database, "globex").await;
        let store = PgOrgSessionStore::new(Arc::clone(&database.databases));
        Fixture {
            database,
            store,
            acme,
            globex,
        }
    }

    /// Saves an organization under `slug` with a tenant and two members
    /// through their stores.
    async fn an_organization(database: &TestDb, slug: &str) -> Held {
        let limits = DomainLimits::default();
        let organization = Organization::reconstitute(organization_row(slug, slug)).unwrap();
        PgOrganizationStore::new(Arc::clone(&database.databases), limits.clone())
            .save(&organization)
            .await
            .unwrap();
        let tenant =
            Tenant::reconstitute(tenant_row(*organization.id(), &format!("{slug}-sales"))).unwrap();
        PgTenantStore::new(Arc::clone(&database.databases), limits.clone())
            .save(&tenant)
            .await
            .unwrap();
        let members = PgOrgUserStore::new(Arc::clone(&database.databases), limits);
        let mut ids = Vec::new();
        for name in ["ann", "bob"] {
            let row = org_user_row(*organization.id(), &format!("{name}@{slug}.example"));
            let member = OrgUser::reconstitute(row).unwrap();
            members.save(&member).await.unwrap();
            ids.push(*member.id());
        }
        Held {
            organization: *organization.id(),
            tenant: *tenant.id(),
            ann: ids.remove(0),
            bob: ids.remove(0),
        }
    }

    fn session(row: OrgSessionRow) -> OrgSession {
        OrgSession::reconstitute(row).unwrap()
    }

    /// An active session of `member` of `held` in its tenant.
    fn in_tenant(held: &Held, member: OrgUserId) -> OrgSessionRow {
        org_session_row(held.organization, member, SessionPlace::Tenant(held.tenant))
    }

    /// A session of Ann in Acme's tenant made `n` seconds after the fixed
    /// moment, last used `11 * n` seconds after it, and expiring `n` seconds later
    /// than the default, so each order lists them by `n`.
    fn made_at(held: &Held, n: i64) -> OrgSession {
        session(OrgSessionRow {
            created_at: at(n),
            last_active_at: at(n.saturating_mul(11)),
            expires_at: at(1_000_000_000_i64.saturating_add(n)),
            ..in_tenant(held, held.ann)
        })
    }

    async fn save_all(store: &PgOrgSessionStore, sessions: &[&OrgSession]) {
        for session in sessions {
            store.save(session).await.unwrap();
        }
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn ids(sessions: &[OrgSession]) -> Vec<SessionId> {
        sessions.iter().map(|session| *session.id()).collect()
    }

    /// Ann signs in to Acme's tenant: the session is found by its id and by
    /// its refresh token as it was saved.
    #[tokio::test]
    async fn a_saved_session_is_found_by_its_id_and_its_refresh_token() {
        let db = fixture().await;
        let signed_in = session(in_tenant(&db.acme, db.acme.ann));

        db.store.save(&signed_in).await.unwrap();

        let by_id = db.store.find_by_id(signed_in.id()).await.unwrap().unwrap();
        let by_token = db
            .store
            .find_by_refresh_token_hash(signed_in.refresh_token_hash())
            .await
            .unwrap()
            .unwrap();
        for found in [&by_id, &by_token] {
            assert_eq!(found.id(), signed_in.id());
            assert_eq!(found.org_user_id(), signed_in.org_user_id());
            assert_eq!(found.organization_id(), signed_in.organization_id());
            assert_eq!(found.place(), SessionPlace::Tenant(db.acme.tenant));
            assert_eq!(found.progress(), signed_in.progress());
            assert_eq!(found.ip_address(), signed_in.ip_address());
            assert_eq!(found.user_agent(), signed_in.user_agent());
            assert_eq!(found.status(), SessionStatus::Active);
            assert_eq!(found.created_at(), signed_in.created_at());
            assert_eq!(found.expires_at(), signed_in.expires_at());
            assert_eq!(found.kept_through(), signed_in.kept_through());
        }
    }

    /// Bob, a billing contact, works on the organization alone, from a
    /// client nobody observed: his session keeps that place and those
    /// unknowns, and his second factor and what is still owed.
    #[tokio::test]
    async fn an_organization_session_keeps_its_place_and_its_unknowns() {
        let db = fixture().await;
        let billing = session(OrgSessionRow {
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::Verify,
            },
            ..org_session_row(
                db.acme.organization,
                db.acme.bob,
                SessionPlace::Organization,
            )
        });

        db.store.save(&billing).await.unwrap();

        let found = db.store.find_by_id(billing.id()).await.unwrap().unwrap();
        assert_eq!(found.place(), SessionPlace::Organization);
        assert_eq!(found.ip_address(), Fact::Unknown);
        assert_eq!(found.user_agent(), Fact::Unknown);
        assert_eq!(found.owed(), SecondFactor::Verify);
    }

    /// An id or refresh token nobody has finds nothing, rather than
    /// failing.
    #[tokio::test]
    async fn an_unknown_session_is_not_found() {
        let db = fixture().await;
        let never_saved = session(in_tenant(&db.acme, db.acme.ann));

        let by_id = db.store.find_by_id(never_saved.id()).await.unwrap();
        let by_token = db
            .store
            .find_by_refresh_token_hash(never_saved.refresh_token_hash())
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(by_token.is_none());
    }

    /// Ann's session is used again and suspended after a rise in risk:
    /// saving it keeps both.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let db = fixture().await;
        let signed_in = session(in_tenant(&db.acme, db.acme.ann));
        db.store.save(&signed_in).await.unwrap();
        let suspended = session(OrgSessionRow {
            id: *signed_in.id(),
            refresh_token_hash: signed_in.refresh_token_hash().clone(),
            status: SessionStatus::Suspended,
            last_active_at: at(30),
            ..in_tenant(&db.acme, db.acme.ann)
        });

        db.store.save(&suspended).await.unwrap();

        let found = db.store.find_by_id(signed_in.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), SessionStatus::Suspended);
        assert_eq!(found.last_active_at(), at(30));
    }

    /// Saving Acme's member's session in Globex's tenant returns an
    /// infrastructure error and leaves the session absent.
    #[tokio::test]
    async fn a_session_in_another_organizations_tenant_is_refused() {
        let db = fixture().await;
        let astray = session(org_session_row(
            db.acme.organization,
            db.acme.ann,
            SessionPlace::Tenant(db.globex.tenant),
        ));

        let saved = db.store.save(&astray).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
        assert!(db.store.find_by_id(astray.id()).await.unwrap().is_none());
    }

    /// An admin pages through Acme's sessions in each order they can ask
    /// for: each page follows the last, and the last says nothing follows.
    #[tokio::test]
    async fn the_sessions_in_force_are_read_page_by_page_in_each_order() {
        let db = fixture().await;
        let (one, two, three) = (
            made_at(&db.acme, 1),
            made_at(&db.acme, 2),
            made_at(&db.acme, 3),
        );
        save_all(&db.store, &[&three, &one, &two]).await;

        for field in [
            OrgSessionSortField::CreatedAt,
            OrgSessionSortField::LastActiveAt,
            OrgSessionSortField::ExpiresAt,
        ] {
            let order = SortOrder::single(Sort::ascending(field));
            let page_one = db
                .store
                .list_active(&db.acme.organization, &order, &first(2))
                .await
                .unwrap();
            let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
            let page_two = db
                .store
                .list_active(&db.acme.organization, &order, &after)
                .await
                .unwrap();

            assert_eq!(ids(&page_one.items), [*one.id(), *two.id()]);
            assert_eq!(ids(&page_two.items), [*three.id()]);
            assert!(!page_two.has_next());
        }
    }

    /// Active-session lists exclude expired, revoked, suspended and
    /// unfinished sessions, with the organization list also excluding
    /// Globex's session.
    #[tokio::test]
    async fn only_sessions_in_force_are_listed() {
        let db = fixture().await;
        let in_force = session(in_tenant(&db.acme, db.acme.ann));
        let [expired, revoked, suspended, unfinished] = excluded_sessions(&db.acme);
        let elsewhere = session(in_tenant(&db.globex, db.globex.ann));
        save_all(
            &db.store,
            &[
                &in_force,
                &expired,
                &revoked,
                &suspended,
                &unfinished,
                &elsewhere,
            ],
        )
        .await;
        let order = SortOrder::single(Sort::descending(OrgSessionSortField::CreatedAt));

        let page = db
            .store
            .list_active(&db.acme.organization, &order, &first(10))
            .await
            .unwrap();
        let anns = db.store.list_active_by_member(&db.acme.ann).await.unwrap();
        let bobs = db.store.list_active_by_member(&db.acme.bob).await.unwrap();

        assert_eq!(ids(&page.items), [*in_force.id()]);
        assert_eq!(ids(&anns), [*in_force.id()]);
        assert!(bobs.is_empty());
    }

    /// Expired, revoked, suspended and unfinished sessions excluded from active reads.
    fn excluded_sessions(held: &Held) -> [OrgSession; 4] {
        let expired = session(expired_org_session_row(held.organization, held.ann));
        let revoked = session(OrgSessionRow {
            status: SessionStatus::Revoked,
            ..in_tenant(held, held.ann)
        });
        let suspended = session(OrgSessionRow {
            status: SessionStatus::Suspended,
            ..in_tenant(held, held.bob)
        });
        let unfinished = session(OrgSessionRow {
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::Verify,
            },
            ..in_tenant(held, held.bob)
        });
        [expired, revoked, suspended, unfinished]
    }

    /// Ann's sessions in force are listed for her newest first, and none of
    /// Bob's.
    #[tokio::test]
    async fn a_members_sessions_in_force_are_listed_newest_first() {
        let db = fixture().await;
        let (older, newer) = (made_at(&db.acme, 1), made_at(&db.acme, 2));
        let bobs = session(in_tenant(&db.acme, db.acme.bob));
        save_all(&db.store, &[&older, &newer, &bobs]).await;

        let anns = db.store.list_active_by_member(&db.acme.ann).await.unwrap();

        assert_eq!(ids(&anns), [*newer.id(), *older.id()]);
    }

    /// Ann signs out: her session is revoked once, and revoking it again,
    /// or one nobody has, revokes nothing.
    #[tokio::test]
    async fn a_session_is_revoked_once() {
        let db = fixture().await;
        let signed_in = session(in_tenant(&db.acme, db.acme.ann));
        db.store.save(&signed_in).await.unwrap();

        let first_time = db.store.revoke_by_id(signed_in.id()).await.unwrap();
        let second_time = db.store.revoke_by_id(signed_in.id()).await.unwrap();
        let nobodys = db.store.revoke_by_id(&SessionId::new()).await.unwrap();

        assert!(first_time);
        assert!(!second_time);
        assert!(!nobodys);
        let found = db.store.find_by_id(signed_in.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), SessionStatus::Revoked);
    }

    /// Saving a stale active copy after revoking Ann's session leaves its
    /// stored status revoked.
    #[tokio::test]
    async fn a_save_never_brings_a_revoked_session_back() {
        let db = fixture().await;
        let stale = session(in_tenant(&db.acme, db.acme.ann));
        db.store.save(&stale).await.unwrap();
        db.store.revoke_by_id(stale.id()).await.unwrap();

        db.store.save(&stale).await.unwrap();

        let found = db.store.find_by_id(stale.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), SessionStatus::Revoked);
    }

    /// Revoking Ann's sessions counts her active and suspended sessions,
    /// leaves the suspended one revoked, and keeps Bob's session active.
    #[tokio::test]
    async fn signing_a_member_out_everywhere_revokes_every_session_of_theirs() {
        let db = fixture().await;
        let active = session(in_tenant(&db.acme, db.acme.ann));
        let suspended = session(OrgSessionRow {
            status: SessionStatus::Suspended,
            ..in_tenant(&db.acme, db.acme.ann)
        });
        let already = session(OrgSessionRow {
            status: SessionStatus::Revoked,
            ..in_tenant(&db.acme, db.acme.ann)
        });
        let bobs = session(in_tenant(&db.acme, db.acme.bob));
        save_all(&db.store, &[&active, &suspended, &already, &bobs]).await;

        let revoked = db.store.revoke_all_by_user(&db.acme.ann).await.unwrap();

        assert_eq!(revoked, 2);
        let resumed = db.store.find_by_id(suspended.id()).await.unwrap().unwrap();
        assert_eq!(resumed.status(), SessionStatus::Revoked);
        let kept = db.store.find_by_id(bobs.id()).await.unwrap().unwrap();
        assert_eq!(kept.status(), SessionStatus::Active);
    }

    /// Acme is closed: every session of its members goes, and Globex's
    /// stay.
    #[tokio::test]
    async fn signing_an_organization_out_revokes_only_its_sessions() {
        let db = fixture().await;
        let anns = session(in_tenant(&db.acme, db.acme.ann));
        let bobs = session(OrgSessionRow {
            status: SessionStatus::Suspended,
            ..in_tenant(&db.acme, db.acme.bob)
        });
        let theirs = session(in_tenant(&db.globex, db.globex.ann));
        save_all(&db.store, &[&anns, &bobs, &theirs]).await;

        let revoked = db
            .store
            .revoke_all_by_org(&db.acme.organization)
            .await
            .unwrap();

        assert_eq!(revoked, 2);
        let kept = db.store.find_by_id(theirs.id()).await.unwrap().unwrap();
        assert_eq!(kept.status(), SessionStatus::Active);
    }

    /// The sweep deletes a session expired past its retention, and keeps
    /// one in force.
    #[tokio::test]
    async fn sessions_expired_past_their_retention_are_purged() {
        let db = fixture().await;
        let in_force = session(in_tenant(&db.acme, db.acme.ann));
        let expired = session(expired_org_session_row(db.acme.organization, db.acme.ann));
        save_all(&db.store, &[&in_force, &expired]).await;

        let purged = db.store.purge_expired(30).await.unwrap();

        assert_eq!(purged, 1);
        assert!(db.store.find_by_id(expired.id()).await.unwrap().is_none());
        assert!(db.store.find_by_id(in_force.id()).await.unwrap().is_some());
    }

    /// Reading a session whose stored user agent contains a line break
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_session_is_refused() {
        let db = fixture().await;
        let signed_in = session(in_tenant(&db.acme, db.acme.ann));
        db.store.save(&signed_in).await.unwrap();
        db.database
            .tamper("UPDATE org_sessions SET user_agent = E'curl\\n/8.0'")
            .await;

        let read = db.store.find_by_id(signed_in.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Reading a password session whose stored factor was changed to a
    /// provider's multifactor proof returns an infrastructure error.
    #[tokio::test]
    async fn a_row_holding_an_unreachable_sign_in_is_refused() {
        let db = fixture().await;
        let signed_in = session(in_tenant(&db.acme, db.acme.ann));
        db.store.save(&signed_in).await.unwrap();
        db.database
            .tamper("UPDATE org_sessions SET factor = 'provider_multi_factor'")
            .await;

        let read = db.store.find_by_id(signed_in.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
