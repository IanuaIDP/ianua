//! How a presented bearer's digest becomes the caller behind it, before
//! the tenant it belongs to is known: the store of the lookup in
//! `ports/shared/caller_tokens.rs`.
//!
//! An organization's sessions and keys and an operator's keys live in the
//! platform's tables, so each is one indexed read there. A tenant's session
//! or key may live in the platform database or in the tenant's own, so it
//! is read in the platform database for every tenant living there and in
//! each database of a tenant living apart, all at once, each read held to
//! a few seconds; a row the platform database still holds for a tenant that
//! moved apart is left out. Only a credential neither revoked nor expired
//! answers; a suspended session answers too, so its holder can lift the
//! suspension, and what it may do is the app's to decide.
//!
//! Deny on doubt: two credentials answering one digest, a tenant that is
//! deleted, or a key made by no one who can act answer no caller; a read
//! that failed answers an error unless another database found the
//! credential, since a digest names one credential at most. This store
//! keeps nothing: `cache::CacheTokenLookup` keeps its answers in front of
//! it, dropped by the events a revocation records.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::oauth::ApiKeyStore as _;
use ianua_app::ports::shared::{ResolvedCaller, TokenLookup};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantId, TokenHash};
use time::OffsetDateTime;

use self::record::{KeyHit, MadeKey, OperatorKeyHit, OrgKeyHit, OrgSessionHit, SessionHit};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::tenant_databases::everywhere::{bounded, everywhere};
use crate::postgres::foundation::unit::scoped;
use crate::postgres::oauth::PgApiKeyStore;

/// The Postgres lookup of the credential a bearer's digest names.
pub struct PgTokenLookup {
    databases: Arc<Databases>,
    api_keys: PgApiKeyStore,
}

impl PgTokenLookup {
    /// A lookup reading `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self {
            api_keys: PgApiKeyStore::new(Arc::clone(&databases)),
            databases,
        }
    }

    /// The live tenant sessions holding `hash` under `scope`.
    async fn sessions(
        &self,
        scope: RowScope,
        hash: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<SessionHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                SessionHit,
                "queries/sessions/live_by_refresh_token.sql",
                hash,
                now
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// The unexpired tenant keys kept as `hash` under `scope`.
    async fn keys(
        &self,
        scope: RowScope,
        hash: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<KeyHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(KeyHit, "queries/api_keys/live_by_hash.sql", hash, now)
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// The organization `tenant` belongs to, or `None` once it is deleted.
    async fn organization_of(
        &self,
        tenant: TenantId,
    ) -> Result<Option<OrganizationId>, DomainError> {
        let found = bounded(scoped(
            &self.databases,
            RowScope::Unscoped,
            async |connection| {
                sqlx::query_file_scalar!("queries/tenants/organization_of.sql", tenant.as_uuid())
                    .fetch_optional(connection)
                    .await
            },
        ))
        .await?;
        Ok(found.map(OrganizationId::from_uuid))
    }

    /// The caller a tenant key `hit` names, once its tenant and its maker
    /// are read.
    async fn key_caller(&self, hit: KeyHit) -> Result<Option<ResolvedCaller>, DomainError> {
        let tenant = hit.tenant();
        let Some(organization) = self.organization_of(tenant).await? else {
            return Ok(None);
        };
        let scope = ScopedTenant::from_verified_credential(tenant);
        let Some(key) = bounded(self.api_keys.find_by_id(&scope, &hit.key())).await? else {
            return Ok(None);
        };
        let made = MadeKey {
            key: hit.key(),
            maker: key.created_by(),
            ends: key.expires_at(),
            tenant,
            organization,
        };
        Ok(made.into_caller())
    }
}

/// The one credential `found` holds, or none.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when two credentials answer one
/// digest, which no credential the platform made can do.
fn the_one<T>(found: Vec<T>) -> Result<Option<T>, DomainError> {
    if found.len() > 1 {
        return Err(DomainError::infra_msg(
            "two credentials answer one bearer's digest",
        ));
    }
    Ok(found.into_iter().next())
}

#[async_trait]
impl TokenLookup for PgTokenLookup {
    async fn find_session_by_token_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        let now = clock::now();
        let found = everywhere(
            &self.databases,
            |scope| self.sessions(scope, token_hash.as_str(), now),
            SessionHit::tenant,
        )
        .await?;
        let Some(hit) = the_one(found)? else {
            return Ok(None);
        };
        let Some(organization) = self.organization_of(hit.tenant()).await? else {
            return Ok(None);
        };
        Ok(Some(hit.into_caller(organization)))
    }

    async fn find_org_session_by_token_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        let now = clock::now();
        let found = bounded(scoped(
            &self.databases,
            RowScope::Unscoped,
            async |connection| {
                sqlx::query_file_as!(
                    OrgSessionHit,
                    "queries/org_sessions/live_by_refresh_token.sql",
                    token_hash.as_str(),
                    now
                )
                .fetch_optional(connection)
                .await
            },
        ))
        .await?;
        Ok(found.map(OrgSessionHit::into_caller))
    }

    async fn find_api_key_by_key_hash(
        &self,
        key_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        let now = clock::now();
        let found = everywhere(
            &self.databases,
            |scope| self.keys(scope, key_hash.as_str(), now),
            KeyHit::tenant,
        )
        .await?;
        let Some(hit) = the_one(found)? else {
            return Ok(None);
        };
        self.key_caller(hit).await
    }

    async fn find_org_api_key_by_hash(
        &self,
        key_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        let now = clock::now();
        let found = bounded(scoped(
            &self.databases,
            RowScope::Unscoped,
            async |connection| {
                sqlx::query_file_as!(
                    OrgKeyHit,
                    "queries/org_api_keys/live_by_hash.sql",
                    key_hash.as_str(),
                    now
                )
                .fetch_optional(connection)
                .await
            },
        ))
        .await?;
        Ok(found.map(OrgKeyHit::into_caller))
    }

    async fn find_operator_key_by_hash(
        &self,
        key_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError> {
        let now = clock::now();
        let found = bounded(scoped(
            &self.databases,
            RowScope::Unscoped,
            async |connection| {
                sqlx::query_file_as!(
                    OperatorKeyHit,
                    "queries/operator_api_keys/live_by_hash.sql",
                    key_hash.as_str(),
                    now
                )
                .fetch_optional(connection)
                .await
            },
        ))
        .await?;
        found.map(OperatorKeyHit::into_caller).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::context::{CallerIdentity, Credential};
    use ianua_app::ports::operator::{OperatorKeyStore, OperatorStore};
    use ianua_app::ports::organization::{OrgApiKeyStore, OrgSessionStore, OrgUserStore};
    use ianua_app::ports::shared::{ApiKeyGenerator, KeyFamily, SessionStore, TokenResolver};
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::authentication::sessions::session::{Session, SessionRow};
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
    use ianua_domain::domains::oauth::clients::api_key::{ApiKey, ApiKeyRow, KeyStanding};
    use ianua_domain::domains::operator::api_key::{OperatorApiKey, OperatorApiKeyRow};
    use ianua_domain::domains::organization::access::api_key::{
        OrgApiKey, OrgApiKeyRow, OrgApiKeyStatus,
    };
    use ianua_domain::domains::organization::access::session::{
        OrgSession, OrgSessionRow, SessionPlace,
    };
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::shared::config::{DomainLimits, SlugLimits};
    use ianua_domain::types::{
        ActorRef, Expiry, OperatorId, OrgUserId, Revocation, TenantSlug, UserId,
    };

    use super::*;
    use crate::crypto::keys::tests::test_root;
    use crate::crypto::{HmacApiKeyGenerator, HmacRefreshTokenGenerator, HmacTokenResolver};
    use crate::postgres::operator::{PgOperatorKeyStore, PgOperatorStore};
    use crate::postgres::organization::{PgOrgApiKeyStore, PgOrgSessionStore, PgOrgUserStore};
    use crate::postgres::shared::PgSessionStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};
    use crate::test_support::rows::authentication::session_row;
    use crate::test_support::rows::identity::from_now;
    use crate::test_support::rows::oauth::{a_person, api_key_row, hash};
    use crate::test_support::rows::operator::{active_operator, operator_key_row};
    use crate::test_support::rows::organization::{org_api_key_row, org_session_row, org_user_row};
    use crate::test_support::rows::tenant::deleted_tenant_row;

    /// A database holding Acme, its tenant and Ada, one of its people.
    struct World {
        db: TestDb,
        lookup: PgTokenLookup,
        organization: OrganizationId,
        tenant: ScopedTenant,
        ada: UserId,
    }

    async fn world() -> World {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let ada = a_person(&db, &tenant, "ada@acme.example").await;
        World {
            lookup: PgTokenLookup::new(Arc::clone(&db.databases)),
            db,
            organization,
            tenant,
            ada,
        }
    }

    fn digest(text: &str) -> TokenHash {
        TokenHash::from_stored(text.to_owned())
    }

    async fn saved_session(databases: &Arc<Databases>, tenant: &ScopedTenant, row: SessionRow) {
        PgSessionStore::new(Arc::clone(databases))
            .save(tenant, &Session::reconstitute(row).unwrap())
            .await
            .unwrap();
    }

    async fn saved_key(world: &World, row: ApiKeyRow) {
        PgApiKeyStore::new(Arc::clone(&world.db.databases))
            .insert(&world.tenant, &ApiKey::reconstitute(row).unwrap())
            .await
            .unwrap();
    }

    async fn a_member(world: &World) -> OrgUserId {
        let member =
            OrgUser::reconstitute(org_user_row(world.organization, "owner@acme.example")).unwrap();
        PgOrgUserStore::new(Arc::clone(&world.db.databases), DomainLimits::default())
            .save(&member)
            .await
            .unwrap();
        *member.id()
    }

    async fn an_operator(world: &World) -> OperatorId {
        let operator = active_operator("olga@ianua.dev");
        PgOperatorStore::new(Arc::clone(&world.db.databases))
            .save(&operator)
            .await
            .unwrap();
        *operator.id()
    }

    /// Persists an organization session after its row passes domain validation.
    async fn save_org_session(store: &PgOrgSessionStore, row: OrgSessionRow) {
        store
            .save(&OrgSession::reconstitute(row).unwrap())
            .await
            .unwrap();
    }

    /// Persists an organization key after its row passes domain validation.
    async fn save_org_key(store: &PgOrgApiKeyStore, row: OrgApiKeyRow) {
        store
            .save(&OrgApiKey::reconstitute(row).unwrap())
            .await
            .unwrap();
    }

    /// A live session's token names the person signed in to it, in their
    /// tenant and organization.
    #[tokio::test]
    async fn a_live_session_names_its_person() {
        let world = world().await;
        let row = session_row(world.ada, "refresh-ada");
        let session = row.id;
        saved_session(&world.db.databases, &world.tenant, row).await;

        let caller = world
            .lookup
            .find_session_by_token_hash(&digest("refresh-ada"))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(caller.identity, CallerIdentity::TenantUser(world.ada));
        assert_eq!(caller.credential, Credential::TenantSession(session));
        assert_eq!(caller.tenant_id, Some(*world.tenant));
        assert_eq!(caller.organization_id, Some(world.organization));
    }

    /// A suspended session still names its person, so they can prove a
    /// second factor and lift the suspension; what it may do is the app's
    /// call.
    #[tokio::test]
    async fn a_suspended_session_still_names_its_person() {
        let world = world().await;
        let row = SessionRow {
            status: SessionStatus::Suspended,
            ..session_row(world.ada, "refresh-held")
        };
        saved_session(&world.db.databases, &world.tenant, row).await;

        let caller = world
            .lookup
            .find_session_by_token_hash(&digest("refresh-held"))
            .await
            .unwrap();

        assert!(caller.is_some());
    }

    /// Revoked, expired and never-issued refresh tokens resolve to no
    /// caller.
    #[tokio::test]
    async fn an_ended_session_names_no_one() {
        let world = world().await;
        let revoked = SessionRow {
            status: SessionStatus::Revoked,
            ..session_row(world.ada, "refresh-revoked")
        };
        let expired = SessionRow {
            signed_in_at: from_now(-7200),
            created_at: from_now(-7200),
            last_active_at: from_now(-7200),
            expires_at: from_now(-60),
            ..session_row(world.ada, "refresh-expired")
        };
        saved_session(&world.db.databases, &world.tenant, revoked).await;
        saved_session(&world.db.databases, &world.tenant, expired).await;

        for token in ["refresh-revoked", "refresh-expired", "refresh-never-issued"] {
            let caller = world
                .lookup
                .find_session_by_token_hash(&digest(token))
                .await
                .unwrap();

            assert!(caller.is_none(), "{token}");
        }
    }

    /// A stored session belonging to a deleted tenant resolves to no caller.
    #[tokio::test]
    async fn a_session_of_a_deleted_tenant_names_no_one() {
        let world = world().await;
        let deleted = Tenant::reconstitute(deleted_tenant_row(world.organization, "gone")).unwrap();
        PgTenantStore::new(Arc::clone(&world.db.databases), DomainLimits::default())
            .save(&deleted)
            .await
            .unwrap();
        let gone = ScopedTenant::for_background(*deleted.id());
        let ghost = a_person(&world.db, &gone, "ghost@acme.example").await;
        saved_session(
            &world.db.databases,
            &gone,
            session_row(ghost, "refresh-ghost"),
        )
        .await;

        let caller = world
            .lookup
            .find_session_by_token_hash(&digest("refresh-ghost"))
            .await
            .unwrap();

        assert!(caller.is_none());
    }

    /// A tenant living in a database of its own has its sessions found
    /// there.
    #[tokio::test]
    async fn a_session_in_a_tenants_own_database_is_found() {
        let world = world().await;
        let own = TestDb::fresh().await;
        let apart = saved_tenant_of(&world.db.databases, world.organization).await;
        world.db.databases.register(*apart, own.as_dedicated());
        let bea = a_person(&world.db, &apart, "bea@acme.example").await;
        saved_session(&world.db.databases, &apart, session_row(bea, "refresh-bea")).await;

        let caller = world
            .lookup
            .find_session_by_token_hash(&digest("refresh-bea"))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(caller.identity, CallerIdentity::TenantUser(bea));
        assert_eq!(caller.tenant_id, Some(*apart));
    }

    /// After a tenant is routed to a dedicated database, a session left
    /// in the platform database resolves to no caller.
    #[tokio::test]
    async fn a_session_left_behind_by_a_move_names_no_one() {
        let world = world().await;
        let own = TestDb::fresh().await;
        let moved = saved_tenant_of(&world.db.databases, world.organization).await;
        let cal = a_person(&world.db, &moved, "cal@acme.example").await;
        saved_session(&world.db.databases, &moved, session_row(cal, "refresh-cal")).await;
        world.db.databases.register(*moved, own.as_dedicated());

        let caller = world
            .lookup
            .find_session_by_token_hash(&digest("refresh-cal"))
            .await
            .unwrap();

        assert!(caller.is_none());
    }

    /// A tenant key names whoever made it: a person of the tenant, or a
    /// member of its organization.
    #[tokio::test]
    async fn a_tenant_key_names_its_maker() {
        let world = world().await;
        let member = a_member(&world).await;
        saved_key(&world, api_key_row("ada", ActorRef::User(world.ada))).await;
        saved_key(&world, api_key_row("owner", ActorRef::OrgUser(member))).await;

        let by_ada = world
            .lookup
            .find_api_key_by_key_hash(&hash("key-ada"))
            .await
            .unwrap()
            .unwrap();
        let by_member = world
            .lookup
            .find_api_key_by_key_hash(&hash("key-owner"))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(by_ada.identity, CallerIdentity::TenantUser(world.ada));
        assert!(matches!(by_ada.credential, Credential::TenantApiKey(_)));
        assert_eq!(by_ada.tenant_id, Some(*world.tenant));
        assert_eq!(by_member.identity, CallerIdentity::OrgUser(member));
    }

    /// Ada's paused tenant key resolves to no caller even without expiry.
    #[tokio::test]
    async fn a_paused_tenant_key_names_no_one() {
        let world = world().await;
        let paused = ApiKeyRow {
            created_at: from_now(-3600),
            standing: KeyStanding::Paused(from_now(-60)),
            ..api_key_row("paused", ActorRef::User(world.ada))
        };
        saved_key(&world, paused).await;

        let caller = world
            .lookup
            .find_api_key_by_key_hash(&hash("key-paused"))
            .await
            .unwrap();

        assert!(caller.is_none());
    }

    /// An expired tenant key resolves to no caller while its row remains
    /// stored.
    #[tokio::test]
    async fn an_expired_tenant_key_names_no_one() {
        let world = world().await;
        let expired = ApiKeyRow {
            expires_at: Expiry::At(from_now(-60)),
            created_at: from_now(-3600),
            ..api_key_row("old", ActorRef::User(world.ada))
        };
        saved_key(&world, expired).await;

        let caller = world
            .lookup
            .find_api_key_by_key_hash(&hash("key-old"))
            .await
            .unwrap();

        assert!(caller.is_none());
    }

    /// A key with an end names its maker a second before it, and no one at
    /// that very instant, with its row still stored for the sweep.
    #[tokio::test]
    async fn a_tenant_key_names_no_one_from_the_instant_of_its_end() {
        let world = world().await;
        let end = from_now(3600).replace_nanosecond(0).unwrap();
        let ending = ApiKeyRow {
            expires_at: Expiry::At(end),
            created_at: from_now(-3600),
            ..api_key_row("ending", ActorRef::User(world.ada))
        };
        saved_key(&world, ending).await;
        let frozen = clock::freeze(end - time::Duration::seconds(1));

        let before = world
            .lookup
            .find_api_key_by_key_hash(&hash("key-ending"))
            .await
            .unwrap();
        frozen.advance_to(end);
        let at_the_end = world
            .lookup
            .find_api_key_by_key_hash(&hash("key-ending"))
            .await
            .unwrap();

        assert_eq!(
            before.map(|caller| caller.kept_until),
            Some(Expiry::At(end)),
            "the caller carries the end a cache may serve it until"
        );
        assert!(at_the_end.is_none());
    }

    /// The caller found a second before `end` carries that end, for a
    /// cache in front of the store, and nobody answers at `end` itself.
    fn assert_ends_at(
        end: OffsetDateTime,
        before: Option<ResolvedCaller>,
        at_the_end: Option<&ResolvedCaller>,
    ) {
        assert_eq!(
            before.map(|caller| caller.kept_until),
            Some(Expiry::At(end)),
            "the caller carries the end a cache may serve it until"
        );
        assert!(at_the_end.is_none(), "nobody answers at the very end");
    }

    /// Ada's session names her a second before its end and no one at that
    /// very instant, with its row still stored.
    #[tokio::test]
    async fn a_session_names_no_one_from_the_instant_of_its_end() {
        let world = world().await;
        let end = from_now(3600).replace_nanosecond(0).unwrap();
        let ending = SessionRow {
            expires_at: end,
            ..session_row(world.ada, "refresh-ending")
        };
        saved_session(&world.db.databases, &world.tenant, ending).await;
        let frozen = clock::freeze(end - time::Duration::seconds(1));

        let before = world
            .lookup
            .find_session_by_token_hash(&digest("refresh-ending"))
            .await
            .unwrap();
        frozen.advance_to(end);
        let at_the_end = world
            .lookup
            .find_session_by_token_hash(&digest("refresh-ending"))
            .await
            .unwrap();

        assert_ends_at(end, before, at_the_end.as_ref());
    }

    /// A member's session names them a second before its end and no one at
    /// that very instant.
    #[tokio::test]
    async fn an_organization_session_names_no_one_from_the_instant_of_its_end() {
        let world = world().await;
        let member = a_member(&world).await;
        let end = from_now(3600).replace_nanosecond(0).unwrap();
        let ending = OrgSessionRow {
            expires_at: end,
            created_at: from_now(-3600),
            ..org_session_row(world.organization, member, SessionPlace::Organization)
        };
        let hash = ending.refresh_token_hash.clone();
        let store = PgOrgSessionStore::new(Arc::clone(&world.db.databases));
        save_org_session(&store, ending).await;
        let frozen = clock::freeze(end - time::Duration::seconds(1));

        let before = world
            .lookup
            .find_org_session_by_token_hash(&hash)
            .await
            .unwrap();
        frozen.advance_to(end);
        let at_the_end = world
            .lookup
            .find_org_session_by_token_hash(&hash)
            .await
            .unwrap();

        assert_ends_at(end, before, at_the_end.as_ref());
    }

    /// A member's key names them a second before its end and no one at
    /// that very instant, with its row still stored.
    #[tokio::test]
    async fn an_organization_key_names_no_one_from_the_instant_of_its_end() {
        let world = world().await;
        let member = a_member(&world).await;
        let end = from_now(3600).replace_nanosecond(0).unwrap();
        let ending = OrgApiKeyRow {
            expires_at: Expiry::At(end),
            created_at: from_now(-3600),
            ..org_api_key_row(world.organization, member, "ending")
        };
        let key_hash = ending.key_hash.clone();
        let store = PgOrgApiKeyStore::new(Arc::clone(&world.db.databases));
        save_org_key(&store, ending).await;
        let frozen = clock::freeze(end - time::Duration::seconds(1));

        let before = world
            .lookup
            .find_org_api_key_by_hash(&key_hash)
            .await
            .unwrap();
        frozen.advance_to(end);
        let at_the_end = world
            .lookup
            .find_org_api_key_by_hash(&key_hash)
            .await
            .unwrap();

        assert_ends_at(end, before, at_the_end.as_ref());
    }

    /// Olga's key names her a second before its end and no one at that
    /// very instant.
    #[tokio::test]
    async fn an_operator_key_names_no_one_from_the_instant_of_its_end() {
        let world = world().await;
        let olga = an_operator(&world).await;
        let end = from_now(3600).replace_nanosecond(0).unwrap();
        let ending = OperatorApiKeyRow {
            expires_at: Expiry::At(end),
            created_at: from_now(-3600),
            ..operator_key_row(olga, "opk_ops_ending")
        };
        PgOperatorKeyStore::new(Arc::clone(&world.db.databases))
            .save(&OperatorApiKey::reconstitute(ending).unwrap())
            .await
            .unwrap();
        let frozen = clock::freeze(end - time::Duration::seconds(1));

        let before = world
            .lookup
            .find_operator_key_by_hash(&digest("hash of opk_ops_ending"))
            .await
            .unwrap();
        frozen.advance_to(end);
        let at_the_end = world
            .lookup
            .find_operator_key_by_hash(&digest("hash of opk_ops_ending"))
            .await
            .unwrap();

        assert_ends_at(end, before, at_the_end.as_ref());
    }

    /// A company key and an operator's key made with no end carry none, so
    /// only the cache's own lifetime limits a copy of them.
    #[tokio::test]
    async fn a_key_made_without_an_end_carries_none() {
        let world = world().await;
        let member = a_member(&world).await;
        let olga = an_operator(&world).await;
        let company_key = org_api_key_row(world.organization, member, "lasting");
        let key_hash = company_key.key_hash.clone();
        save_org_key(
            &PgOrgApiKeyStore::new(Arc::clone(&world.db.databases)),
            company_key,
        )
        .await;
        PgOperatorKeyStore::new(Arc::clone(&world.db.databases))
            .save(&OperatorApiKey::reconstitute(operator_key_row(olga, "opk_ops_lasting")).unwrap())
            .await
            .unwrap();

        let company = world
            .lookup
            .find_org_api_key_by_hash(&key_hash)
            .await
            .unwrap();
        let operator = world
            .lookup
            .find_operator_key_by_hash(&digest("hash of opk_ops_lasting"))
            .await
            .unwrap();

        assert_eq!(company.map(|caller| caller.kept_until), Some(Expiry::Never));
        assert_eq!(
            operator.map(|caller| caller.kept_until),
            Some(Expiry::Never)
        );
    }

    /// A member's session names them, on their organization and in no
    /// tenant; a revoked one names no one.
    #[tokio::test]
    async fn an_organization_session_names_its_member() {
        let world = world().await;
        let member = a_member(&world).await;
        let live = org_session_row(world.organization, member, SessionPlace::Organization);
        let ended = OrgSessionRow {
            status: SessionStatus::Revoked,
            created_at: from_now(-3600),
            ..org_session_row(world.organization, member, SessionPlace::Organization)
        };
        let (live_hash, ended_hash) = (
            live.refresh_token_hash.clone(),
            ended.refresh_token_hash.clone(),
        );
        let store = PgOrgSessionStore::new(Arc::clone(&world.db.databases));
        save_org_session(&store, live).await;
        save_org_session(&store, ended).await;

        let caller = world
            .lookup
            .find_org_session_by_token_hash(&live_hash)
            .await
            .unwrap()
            .unwrap();
        let revoked = world
            .lookup
            .find_org_session_by_token_hash(&ended_hash)
            .await
            .unwrap();

        assert_eq!(caller.identity, CallerIdentity::OrgUser(member));
        assert_eq!(caller.organization_id, Some(world.organization));
        assert_eq!(caller.tenant_id, None);
        assert!(revoked.is_none());
    }

    /// A member's key names them; a revoked one names no one.
    #[tokio::test]
    async fn an_organization_key_names_its_member() {
        let world = world().await;
        let member = a_member(&world).await;
        let live = org_api_key_row(world.organization, member, "cli");
        let ended = OrgApiKeyRow {
            status: OrgApiKeyStatus::Revoked,
            ..org_api_key_row(world.organization, member, "old")
        };
        let (live_hash, ended_hash) = (live.key_hash.clone(), ended.key_hash.clone());
        let store = PgOrgApiKeyStore::new(Arc::clone(&world.db.databases));
        save_org_key(&store, live).await;
        save_org_key(&store, ended).await;

        let caller = world
            .lookup
            .find_org_api_key_by_hash(&live_hash)
            .await
            .unwrap()
            .unwrap();
        let revoked = world
            .lookup
            .find_org_api_key_by_hash(&ended_hash)
            .await
            .unwrap();

        assert_eq!(caller.identity, CallerIdentity::OrgUser(member));
        assert!(matches!(caller.credential, Credential::OrgApiKey(_)));
        assert!(revoked.is_none());
    }

    /// An operator's key names them by its prefix; a revoked one names no
    /// one.
    #[tokio::test]
    async fn an_operator_key_names_its_operator() {
        let world = world().await;
        let olga = an_operator(&world).await;
        let ended = OperatorApiKeyRow {
            revocation: Revocation::Revoked { at: at(6) },
            ..operator_key_row(olga, "opk_ops_old")
        };
        let store = PgOperatorKeyStore::new(Arc::clone(&world.db.databases));
        store
            .save(&OperatorApiKey::reconstitute(operator_key_row(olga, "opk_ops_cli")).unwrap())
            .await
            .unwrap();
        store
            .save(&OperatorApiKey::reconstitute(ended).unwrap())
            .await
            .unwrap();

        let caller = world
            .lookup
            .find_operator_key_by_hash(&digest("hash of opk_ops_cli"))
            .await
            .unwrap()
            .unwrap();
        let revoked = world
            .lookup
            .find_operator_key_by_hash(&digest("hash of opk_ops_old"))
            .await
            .unwrap();

        assert_eq!(caller.identity, CallerIdentity::Operator(olga));
        assert!(matches!(caller.credential, Credential::OperatorKey(_)));
        assert!(revoked.is_none());
    }

    /// A key and a refresh token as the platform hands them out resolve,
    /// through the resolver's digests, to the people they belong to.
    #[tokio::test]
    async fn a_handed_out_key_and_token_resolve_to_their_holders() {
        let world = world().await;
        let slug = TenantSlug::new("acme", &SlugLimits::default()).unwrap();
        let made = HmacApiKeyGenerator::new(&test_root())
            .generate(KeyFamily::Tenant, &slug)
            .await
            .unwrap();
        let row = ApiKeyRow {
            key_prefix: made.key_prefix.clone(),
            key_hash: made.key_hash.clone(),
            ..api_key_row("cli", ActorRef::User(world.ada))
        };
        saved_key(&world, row).await;
        let token = HmacRefreshTokenGenerator::new(&test_root())
            .generate()
            .unwrap();
        let session = session_row(world.ada, token.hash().as_str());
        saved_session(&world.db.databases, &world.tenant, session).await;
        let lookup = Arc::new(PgTokenLookup::new(Arc::clone(&world.db.databases)));
        let resolver = HmacTokenResolver::new(&test_root(), lookup);

        let by_key = resolver.resolve(&made.raw_key).await.unwrap().unwrap();
        let by_token = resolver.resolve(token.raw()).await.unwrap().unwrap();

        assert_eq!(by_key.identity, CallerIdentity::TenantUser(world.ada));
        assert!(matches!(by_key.credential, Credential::TenantApiKey(_)));
        assert!(matches!(by_token.credential, Credential::TenantSession(_)));
    }
}
