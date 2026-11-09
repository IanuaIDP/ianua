//! A tenant's issued access tokens, each found by its hash, under
//! row-level security.
//!
//! Only a token's hash is kept. A save never undoes a revocation, so a copy
//! read before a person withdrew their consent cannot bring its token back.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::AccessTokenStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::grants::access_token::AccessToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OAuthClientId, TokenHash, UserId};
use time::OffsetDateTime;

use self::record::{AccessTokenColumns, AccessTokenRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of issued access tokens.
pub struct PgAccessTokenStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAccessTokenStore {}

impl PgAccessTokenStore {
    /// A store keeping access tokens in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AccessTokenStore for PgAccessTokenStore {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<AccessToken<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AccessTokenRecord,
                    "queries/oauth_access_tokens/by_hash.sql",
                    tenant_id.as_uuid(),
                    token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(AccessTokenRecord::into_token).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &AccessToken<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = AccessTokenColumns::of(token)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_access_tokens/save.sql",
                    tenant_id.as_uuid(),
                    columns.token_hash,
                    columns.client_id,
                    columns.user_id,
                    columns.scopes.as_slice(),
                    columns.audience_client_id,
                    columns.audience_stream_route_id,
                    columns.delegation,
                    columns.binding,
                    columns.binding_thumbprint,
                    columns.created_at,
                    columns.expires_at,
                    columns.revoked_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn revoke_grant(
        &self,
        tenant_id: &ScopedTenant,
        person: &UserId,
        client: &OAuthClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_access_tokens/revoke_grant.sql",
                    tenant_id.as_uuid(),
                    person.as_uuid(),
                    client.as_uuid(),
                    now
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::routing::StreamRouteStore;
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::grants::access_token::{
        AccessAudience, AccessTokenRow, ActingParty, TokenSubject,
    };
    use ianua_domain::domains::oauth::grants::token_binding::{JwkThumbprint, SenderBinding};
    use ianua_domain::domains::routing::stream::StreamRoute;
    use ianua_domain::types::{Revocation, StreamRouteId};

    use super::*;
    use crate::postgres::routing::PgStreamRouteStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::domain::saved_tenant;
    use crate::test_support::rows::oauth::{
        a_client, a_person, access_row, hash, oauth_client_row,
    };
    use crate::test_support::rows::routing::stream_route_row;

    struct Fixture {
        db: TestDb,
        store: PgAccessTokenStore,
        tenant: ScopedTenant,
        portal: OAuthClient<ResolvedTenant>,
        ann: UserId,
    }

    /// A fresh database, the store on it, and a tenant with a client and a
    /// person it holds tokens for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = saved_tenant(&db.databases).await;
        let portal = a_client(
            &db,
            &tenant,
            oauth_client_row("portal", &[GrantType::AuthorizationCode]),
        )
        .await;
        let ann = a_person(&db, &tenant, "ann@acme.example").await;
        Fixture {
            store: PgAccessTokenStore::new(Arc::clone(&db.databases)),
            db,
            tenant,
            portal,
            ann,
        }
    }

    fn token(row: AccessTokenRow) -> AccessToken<ResolvedTenant> {
        AccessToken::reconstitute(row).unwrap()
    }

    impl Fixture {
        /// Saves another code-flow client in Ann's tenant for grant-isolation checks.
        async fn code_client(&self, name: &str) -> OAuthClient<ResolvedTenant> {
            a_client(
                &self.db,
                &self.tenant,
                oauth_client_row(name, &[GrantType::AuthorizationCode]),
            )
            .await
        }

        fn anns(&self, raw: &str) -> AccessTokenRow {
            access_row(&self.portal, TokenSubject::Person(self.ann), raw)
        }

        async fn revocation_of(&self, raw: &str) -> Option<OffsetDateTime> {
            self.store
                .find_by_hash(&self.tenant, &hash(raw))
                .await
                .unwrap()
                .unwrap()
                .revoked_at()
        }
    }

    /// A token exchanged for another client, acting through it and bound to
    /// a DPoP key, is found by its hash as it was saved.
    #[tokio::test]
    async fn a_saved_token_is_found_by_its_hash() {
        let db = fixture().await;
        let api = a_client(
            &db.db,
            &db.tenant,
            oauth_client_row("api", &[GrantType::TokenExchange]),
        )
        .await;
        let exchanged = token(AccessTokenRow {
            audience: AccessAudience::Client(*api.id()),
            delegation: vec![ActingParty::Client(*db.portal.id())],
            binding: SenderBinding::DpopKey(
                JwkThumbprint::new("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs").unwrap(),
            ),
            ..db.anns("access-1")
        });

        db.store.save(&db.tenant, &exchanged).await.unwrap();

        let found = db
            .store
            .find_by_hash(&db.tenant, exchanged.token_hash())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.client_id(), db.portal.id());
        assert_eq!(found.subject(), TokenSubject::Person(db.ann));
        assert_eq!(found.scopes(), exchanged.scopes());
        assert_eq!(found.audience(), AccessAudience::Client(*api.id()));
        assert_eq!(found.delegation(), exchanged.delegation());
        assert_eq!(found.binding(), exchanged.binding());
        assert_eq!(found.expires_at(), exchanged.expires_at());
        assert_eq!(found.revoked_at(), None);
    }

    /// Ann's token for the SSH tunnel is found meant for that stream route.
    #[tokio::test]
    async fn a_tunnel_token_is_found_meant_for_its_route() {
        let db = fixture().await;
        let route = StreamRoute::reconstitute(stream_route_row("ssh", 2222)).unwrap();
        let ssh = *route.id();
        PgStreamRouteStore::new(Arc::clone(&db.db.databases))
            .save(&db.tenant, &route)
            .await
            .unwrap();
        let tunnel = token(AccessTokenRow {
            audience: AccessAudience::StreamRoute(ssh),
            ..db.anns("access-1")
        });

        db.store.save(&db.tenant, &tunnel).await.unwrap();

        let found = db
            .store
            .find_by_hash(&db.tenant, tunnel.token_hash())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.audience(), AccessAudience::StreamRoute(ssh));
    }

    /// Saving an access token for an absent stream route fails.
    #[tokio::test]
    async fn a_tunnel_token_for_no_route_is_refused() {
        let db = fixture().await;
        let tunnel = token(AccessTokenRow {
            audience: AccessAudience::StreamRoute(StreamRouteId::new()),
            ..db.anns("access-1")
        });

        let saved = db.store.save(&db.tenant, &tunnel).await;

        assert!(saved.is_err());
    }

    /// A client acting as itself holds a token for no person.
    #[tokio::test]
    async fn a_token_for_the_client_itself_names_no_person() {
        let db = fixture().await;
        let own = token(access_row(&db.portal, TokenSubject::Client, "access-1"));

        db.store.save(&db.tenant, &own).await.unwrap();

        let found = db
            .store
            .find_by_hash(&db.tenant, own.token_hash())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.subject(), TokenSubject::Client);
    }

    /// An unknown token hash and another tenant's token hash both return nothing.
    #[tokio::test]
    async fn a_token_is_found_only_by_its_tenant() {
        let db = fixture().await;
        let issued = token(db.anns("access-1"));
        db.store.save(&db.tenant, &issued).await.unwrap();

        let unknown = db
            .store
            .find_by_hash(&db.tenant, &hash("nobody"))
            .await
            .unwrap();
        let theirs = db
            .store
            .find_by_hash(&tenant(), issued.token_hash())
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
    }

    /// Saving an unrevoked copy preserves the access token's stored revocation
    /// time.
    #[tokio::test]
    async fn a_save_never_undoes_a_revocation() {
        let db = fixture().await;
        let revoked = token(AccessTokenRow {
            revocation: Revocation::Revoked { at: at(5) },
            ..db.anns("access-1")
        });
        db.store.save(&db.tenant, &revoked).await.unwrap();

        db.store
            .save(&db.tenant, &token(db.anns("access-1")))
            .await
            .unwrap();

        assert_eq!(db.revocation_of("access-1").await, Some(at(5)));
    }

    /// Ann withdraws her consent to the portal: its tokens for her are
    /// revoked, one revoked before keeps its time, and its tokens for Bob
    /// and the reports app's for Ann keep working.
    #[tokio::test]
    async fn revoking_a_grant_ends_only_that_clients_tokens_for_that_person() {
        let db = fixture().await;
        let bob = a_person(&db.db, &db.tenant, "bob@acme.example").await;
        let reports = db.code_client("reports").await;
        let earlier = token(AccessTokenRow {
            revocation: Revocation::Revoked { at: at(5) },
            ..db.anns("earlier")
        });
        for issued in [
            token(db.anns("live")),
            earlier,
            token(access_row(&db.portal, TokenSubject::Person(bob), "bobs")),
            token(access_row(
                &reports,
                TokenSubject::Person(db.ann),
                "reports",
            )),
        ] {
            db.store.save(&db.tenant, &issued).await.unwrap();
        }

        db.store
            .revoke_grant(&db.tenant, &db.ann, db.portal.id(), at(10))
            .await
            .unwrap();

        assert_eq!(db.revocation_of("live").await, Some(at(10)));
        assert_eq!(db.revocation_of("earlier").await, Some(at(5)));
        assert_eq!(db.revocation_of("bobs").await, None);
        assert_eq!(db.revocation_of("reports").await, None);
    }

    /// Reading an access token with an invalid stored DPoP thumbprint returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_token_is_refused() {
        let db = fixture().await;
        let issued = token(db.anns("access-1"));
        db.store.save(&db.tenant, &issued).await.unwrap();
        db.db
            .tamper("UPDATE oauth_access_tokens SET binding = 'dpop', binding_thumbprint = 'short'")
            .await;

        let read = db.store.find_by_hash(&db.tenant, issued.token_hash()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
