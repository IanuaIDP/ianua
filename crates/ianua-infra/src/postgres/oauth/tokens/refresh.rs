//! A tenant's refresh tokens, each found by its hash, under row-level
//! security.
//!
//! Only a token's hash is kept. Every write that ends a token is one
//! `UPDATE` that touches only tokens still active, so a token rotated or
//! revoked meanwhile keeps the time it stopped working. A rotation retires
//! the used token and keeps the next in one store call, so of two refreshes
//! with one token only the one that retired it gets the next; the other
//! revokes the family in the same transaction, since one token presented
//! twice is a copy in use.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::{RefreshRotation, RefreshTokenStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::grants::refresh_token::OAuthRefreshToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OAuthClientId, RefreshFamilyId, SessionId, TokenHash, UserId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{RefreshTokenColumns, RefreshTokenRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of refresh tokens.
pub struct PgRefreshTokenStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgRefreshTokenStore {}

impl PgRefreshTokenStore {
    /// A store keeping refresh tokens in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// Keeps the token `columns` describes in `tenant`.
async fn insert_row(
    connection: &mut PgConnection,
    tenant: &Uuid,
    columns: &RefreshTokenColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/oauth_refresh_tokens/insert.sql",
        tenant,
        columns.token_hash,
        columns.family_id,
        columns.client_id,
        columns.user_id,
        columns.scopes.as_slice(),
        columns.session_id,
        columns.binding,
        columns.binding_thumbprint,
        columns.issued_at,
        columns.expires_at,
        columns.family_expires_at,
        columns.state,
        columns.ended_at,
    )
    .execute(connection)
    .await
    .map(|_| ())
}

/// Writes how the token `columns` describes ended, while it is still
/// active, and says whether it was.
async fn retired(
    connection: &mut PgConnection,
    tenant: &Uuid,
    columns: &RefreshTokenColumns<'_>,
) -> Result<bool, sqlx::Error> {
    let retired = sqlx::query_file!(
        "queries/oauth_refresh_tokens/retire.sql",
        tenant,
        columns.token_hash,
        columns.state,
        columns.ended_at
    )
    .execute(connection)
    .await?;
    Ok(retired.rows_affected() == 1)
}

/// How a rotation of the token `used` describes, turned down because the
/// stored one was no longer active, answers. One another refresh rotated
/// first is a copy in use: every active token of its family is revoked, at
/// the time `used` was rotated, in the same transaction.
async fn turned_down(
    connection: &mut PgConnection,
    tenant: &Uuid,
    used: &RefreshTokenColumns<'_>,
) -> Result<RefreshRotation, sqlx::Error> {
    let state = sqlx::query_file_scalar!(
        "queries/oauth_refresh_tokens/state.sql",
        tenant,
        used.token_hash
    )
    .fetch_optional(&mut *connection)
    .await?;
    if state.as_deref() != Some("rotated") {
        return Ok(RefreshRotation::Ended);
    }
    sqlx::query_file!(
        "queries/oauth_refresh_tokens/revoke_family.sql",
        tenant,
        used.family_id,
        used.ended_at.unwrap_or_else(clock::now)
    )
    .execute(connection)
    .await?;
    Ok(RefreshRotation::Reused)
}

#[async_trait]
impl RefreshTokenStore for PgRefreshTokenStore {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<OAuthRefreshToken<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RefreshTokenRecord,
                    "queries/oauth_refresh_tokens/by_hash.sql",
                    tenant_id.as_uuid(),
                    token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(RefreshTokenRecord::into_token).transpose()
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        token: &OAuthRefreshToken<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let row = token.to_row();
        let columns = RefreshTokenColumns::of(&row);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| insert_row(connection, tenant_id.as_uuid(), &columns).await,
        )
        .await
    }

    async fn rotate(
        &self,
        tenant_id: &ScopedTenant,
        used: &OAuthRefreshToken<ResolvedTenant>,
        next: &OAuthRefreshToken<ResolvedTenant>,
    ) -> Result<RefreshRotation, DomainError> {
        let (used_row, next_row) = (used.to_row(), next.to_row());
        let (used, next) = (
            RefreshTokenColumns::of(&used_row),
            RefreshTokenColumns::of(&next_row),
        );
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                if !retired(&mut *connection, tenant_id.as_uuid(), &used).await? {
                    return turned_down(connection, tenant_id.as_uuid(), &used).await;
                }
                insert_row(connection, tenant_id.as_uuid(), &next).await?;
                Ok(RefreshRotation::Rotated)
            },
        )
        .await
    }

    async fn revoke_family(
        &self,
        tenant_id: &ScopedTenant,
        family: &RefreshFamilyId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_refresh_tokens/revoke_family.sql",
                    tenant_id.as_uuid(),
                    family.as_uuid(),
                    now
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn revoke_session(
        &self,
        tenant_id: &ScopedTenant,
        session: &SessionId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_refresh_tokens/revoke_session.sql",
                    tenant_id.as_uuid(),
                    session.as_uuid(),
                    now
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
                    "queries/oauth_refresh_tokens/revoke_grant.sql",
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
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::grants::refresh_token::{
        GrantedIn, OAuthRefreshTokenRow, RefreshState,
    };

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authentication::session_of;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::oauth::{
        a_client, a_person, hash, oauth_client_row, refresh_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgRefreshTokenStore,
        tenant: ScopedTenant,
        portal: OAuthClient<ResolvedTenant>,
        ann: UserId,
        session: SessionId,
    }

    /// A fresh database, the store on it, and a tenant with a client and a
    /// person it holds tokens for, granted in one session.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let portal = a_client(
            &db,
            &tenant,
            oauth_client_row(
                "portal",
                &[GrantType::AuthorizationCode, GrantType::RefreshToken],
            ),
        )
        .await;
        let ann = a_person(&db, &tenant, "ann@acme.example").await;
        let session = session_of(&db.databases, &tenant, ann).await;
        Fixture {
            store: PgRefreshTokenStore::new(Arc::clone(&db.databases)),
            db,
            tenant,
            portal,
            ann,
            session,
        }
    }

    fn token(row: OAuthRefreshTokenRow) -> OAuthRefreshToken<ResolvedTenant> {
        OAuthRefreshToken::reconstitute(row).unwrap()
    }

    /// Issues a replacement in the original token family at the shared rotation time.
    fn replacement(row: OAuthRefreshTokenRow, raw: &str) -> OAuthRefreshToken<ResolvedTenant> {
        token(OAuthRefreshTokenRow {
            token_hash: hash(raw),
            issued_at: at(5),
            ..row
        })
    }

    impl Fixture {
        fn anns(&self, raw: &str) -> OAuthRefreshTokenRow {
            refresh_row(&self.portal, self.ann, self.session, raw)
        }

        async fn kept(&self, rows: Vec<OAuthRefreshTokenRow>) {
            for row in rows {
                self.store.insert(&self.tenant, &token(row)).await.unwrap();
            }
        }

        async fn state_of(&self, raw: &str) -> RefreshState {
            self.store
                .find_by_hash(&self.tenant, &hash(raw))
                .await
                .unwrap()
                .unwrap()
                .state()
        }
    }

    /// A token granted on a second screen is found by its hash as it was
    /// kept.
    #[tokio::test]
    async fn a_kept_token_is_found_by_its_hash() {
        let db = fixture().await;
        let device = token(OAuthRefreshTokenRow {
            granted_in: GrantedIn::DeviceApproval,
            ..db.anns("refresh-1")
        });

        db.store.insert(&db.tenant, &device).await.unwrap();

        let found = db
            .store
            .find_by_hash(&db.tenant, device.token_hash())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.to_row().granted_in, GrantedIn::DeviceApproval);
        assert_eq!(found.family(), device.family());
        assert_eq!(found.user_id(), &db.ann);
        assert!(found.belongs_to(db.portal.id()));
        assert_eq!(found.scopes(), device.scopes());
        assert_eq!(found.binding(), device.binding());
        assert_eq!(found.expires_at(), device.expires_at());
        assert_eq!(found.state(), RefreshState::Active);
    }

    /// Unknown refresh-token hashes and lookups from another tenant return
    /// nothing.
    #[tokio::test]
    async fn a_token_is_found_only_by_its_tenant() {
        let db = fixture().await;
        db.kept(vec![db.anns("refresh-1")]).await;

        let unknown = db
            .store
            .find_by_hash(&db.tenant, &hash("nobody"))
            .await
            .unwrap();
        let theirs = db
            .store
            .find_by_hash(&tenant(), &hash("refresh-1"))
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
    }

    /// A second rotation of the same token reports reuse and revokes the first
    /// replacement at the rotation time, without keeping the rival replacement.
    /// The original token retains its rotated state.
    #[tokio::test]
    async fn a_token_is_rotated_once() {
        let db = fixture().await;
        let first = db.anns("refresh-1");
        db.kept(vec![first.clone()]).await;
        let used = token(OAuthRefreshTokenRow {
            state: RefreshState::Rotated { at: at(5) },
            ..first.clone()
        });
        let next = replacement(first.clone(), "refresh-2");
        let rival = replacement(first, "refresh-3");

        let won = db.store.rotate(&db.tenant, &used, &next).await.unwrap();
        let lost = db.store.rotate(&db.tenant, &used, &rival).await.unwrap();

        assert_eq!(won, RefreshRotation::Rotated);
        assert_eq!(lost, RefreshRotation::Reused);
        assert_eq!(
            db.state_of("refresh-1").await,
            RefreshState::Rotated { at: at(5) }
        );
        assert_eq!(
            db.state_of("refresh-2").await,
            RefreshState::Revoked { at: at(5) }
        );
        let rivals = db
            .store
            .find_by_hash(&db.tenant, &hash("refresh-3"))
            .await
            .unwrap();
        assert!(rivals.is_none());
    }

    /// A token revoked by signing out while a refresh with it was under
    /// way is not rotated, and is not taken for reuse: the rotation is
    /// answered as ended and keeps nothing.
    #[tokio::test]
    async fn a_token_revoked_meanwhile_is_not_rotated() {
        let db = fixture().await;
        let first = db.anns("refresh-1");
        db.kept(vec![first.clone()]).await;
        db.store
            .revoke_session(&db.tenant, &db.session, at(3))
            .await
            .unwrap();
        let used = token(OAuthRefreshTokenRow {
            state: RefreshState::Rotated { at: at(5) },
            ..first.clone()
        });
        let next = token(OAuthRefreshTokenRow {
            token_hash: hash("refresh-2"),
            issued_at: at(5),
            ..first
        });

        let rotation = db.store.rotate(&db.tenant, &used, &next).await.unwrap();

        assert_eq!(rotation, RefreshRotation::Ended);
        assert_eq!(
            db.state_of("refresh-1").await,
            RefreshState::Revoked { at: at(3) }
        );
        let kept = db
            .store
            .find_by_hash(&db.tenant, &hash("refresh-2"))
            .await
            .unwrap();
        assert!(kept.is_none());
    }

    /// A rotated token presented again ends its family: its active tokens
    /// are revoked, the rotated one keeps its time, and another family is
    /// left alone.
    #[tokio::test]
    async fn revoking_a_family_ends_only_its_active_tokens() {
        let db = fixture().await;
        let first = db.anns("refresh-1");
        let rotated = OAuthRefreshTokenRow {
            state: RefreshState::Rotated { at: at(5) },
            ..first.clone()
        };
        let current = OAuthRefreshTokenRow {
            token_hash: hash("refresh-2"),
            ..first.clone()
        };
        db.kept(vec![rotated, current, db.anns("other-family")])
            .await;

        db.store
            .revoke_family(&db.tenant, &first.family, at(10))
            .await
            .unwrap();

        assert_eq!(
            db.state_of("refresh-1").await,
            RefreshState::Rotated { at: at(5) }
        );
        assert_eq!(
            db.state_of("refresh-2").await,
            RefreshState::Revoked { at: at(10) }
        );
        assert_eq!(db.state_of("other-family").await, RefreshState::Active);
    }

    /// Ann signs out of a session: the tokens granted in it are revoked,
    /// and those of another session are left alone.
    #[tokio::test]
    async fn revoking_a_session_ends_only_the_tokens_granted_in_it() {
        let db = fixture().await;
        let elsewhere = OAuthRefreshTokenRow {
            granted_in: GrantedIn::Session(session_of(&db.db.databases, &db.tenant, db.ann).await),
            ..db.anns("elsewhere")
        };
        db.kept(vec![db.anns("here"), elsewhere]).await;

        db.store
            .revoke_session(&db.tenant, &db.session, at(10))
            .await
            .unwrap();

        assert_eq!(
            db.state_of("here").await,
            RefreshState::Revoked { at: at(10) }
        );
        assert_eq!(db.state_of("elsewhere").await, RefreshState::Active);
    }

    /// Ann withdraws her consent to the portal: its tokens for her are
    /// revoked, and its tokens for Bob are left alone.
    #[tokio::test]
    async fn revoking_a_grant_ends_only_that_persons_tokens() {
        let db = fixture().await;
        let bob = a_person(&db.db, &db.tenant, "bob@acme.example").await;
        let bobs = refresh_row(&db.portal, bob, db.session, "bobs");
        db.kept(vec![db.anns("anns"), bobs]).await;

        db.store
            .revoke_grant(&db.tenant, &db.ann, db.portal.id(), at(10))
            .await
            .unwrap();

        assert_eq!(
            db.state_of("anns").await,
            RefreshState::Revoked { at: at(10) }
        );
        assert_eq!(db.state_of("bobs").await, RefreshState::Active);
    }

    /// Reading a refresh token with an invalid stored scope returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_token_is_refused() {
        let db = fixture().await;
        db.kept(vec![db.anns("refresh-1")]).await;
        db.db
            .tamper("UPDATE oauth_refresh_tokens SET scopes = ARRAY['not a scope']")
            .await;

        let read = db.store.find_by_hash(&db.tenant, &hash("refresh-1")).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
