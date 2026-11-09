//! The scopes each person of a tenant gave each client, one row per pair,
//! under row-level security. A withdrawn consent stays, holding no scope.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::OAuthConsentStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::clients::consent::OAuthConsent;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OAuthClientId, UserId};

use self::record::ConsentRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::oauth::scopes::scopes_column;

/// The Postgres store of OAuth consents.
pub struct PgOAuthConsentStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgOAuthConsentStore {}

impl PgOAuthConsentStore {
    /// A store keeping consents in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OAuthConsentStore for PgOAuthConsentStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        client_id: &OAuthClientId,
    ) -> Result<Option<OAuthConsent<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ConsentRecord,
                    "queries/oauth_consents/find.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    client_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ConsentRecord::into_consent).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        consent: &OAuthConsent<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let scopes = scopes_column(consent.scopes());
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_consents/save.sql",
                    tenant_id.as_uuid(),
                    consent.user_id().as_uuid(),
                    consent.client_id().as_uuid(),
                    scopes.as_slice(),
                    consent.granted_at()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn list_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<OAuthConsent<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ConsentRecord,
                    "queries/oauth_consents/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(ConsentRecord::into_consent)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::clients::consent::OAuthConsentRow;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::oauth::{
        a_client, a_person, consent_row, oauth_client_row, scopes,
    };

    struct Fixture {
        db: TestDb,
        store: PgOAuthConsentStore,
        tenant: ScopedTenant,
        portal: OAuthClient<ResolvedTenant>,
        ann: UserId,
    }

    /// A fresh database, the store on it, and a tenant with a client and a
    /// person to consent to it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let portal = a_client(
            &db,
            &tenant,
            oauth_client_row("portal", &[GrantType::AuthorizationCode]),
        )
        .await;
        let ann = a_person(&db, &tenant, "ann@acme.example").await;
        Fixture {
            store: PgOAuthConsentStore::new(Arc::clone(&db.databases)),
            db,
            tenant,
            portal,
            ann,
        }
    }

    fn consent(row: OAuthConsentRow) -> OAuthConsent<ResolvedTenant> {
        OAuthConsent::reconstitute(row).unwrap()
    }

    /// Ann's consent to the portal is found by her and the portal, with the
    /// scopes she gave.
    #[tokio::test]
    async fn a_saved_consent_is_found_by_person_and_client() {
        let db = fixture().await;
        let given = consent(consent_row(db.ann, &db.portal, 1));

        db.store.save(&db.tenant, &given).await.unwrap();

        let found = db
            .store
            .find(&db.tenant, &db.ann, db.portal.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.scopes(), given.scopes());
        assert_eq!(found.granted_at(), at(1));
    }

    /// A pair nobody consented for finds nothing, and another tenant finds
    /// none of this tenant's consents.
    #[tokio::test]
    async fn a_consent_is_found_only_by_its_tenant() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &consent(consent_row(db.ann, &db.portal, 1)))
            .await
            .unwrap();
        let globex = tenant();

        let unknown = db
            .store
            .find(&db.tenant, &UserId::new(), db.portal.id())
            .await
            .unwrap();
        let theirs = db
            .store
            .find(&globex, &db.ann, db.portal.id())
            .await
            .unwrap();
        let listed = db.store.list_for_user(&globex, &db.ann).await.unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
        assert!(listed.is_empty());
    }

    /// Ann gives more scopes later: saving again keeps them and the new
    /// time, in the one row of the pair.
    #[tokio::test]
    async fn saving_again_keeps_the_new_scopes() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &consent(consent_row(db.ann, &db.portal, 1)))
            .await
            .unwrap();
        let widened = consent(OAuthConsentRow {
            scopes: scopes(&["openid", "read"]),
            ..consent_row(db.ann, &db.portal, 7)
        });

        db.store.save(&db.tenant, &widened).await.unwrap();

        let listed = db.store.list_for_user(&db.tenant, &db.ann).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].scopes(), widened.scopes());
        assert_eq!(listed[0].granted_at(), at(7));
    }

    /// Ann's consents are listed newest first, a withdrawn one too.
    #[tokio::test]
    async fn a_persons_consents_are_listed_newest_first() {
        let db = fixture().await;
        let reports = a_client(
            &db.db,
            &db.tenant,
            oauth_client_row("reports", &[GrantType::AuthorizationCode]),
        )
        .await;
        let withdrawn = consent(OAuthConsentRow {
            scopes: Vec::new(),
            ..consent_row(db.ann, &reports, 9)
        });
        db.store
            .save(&db.tenant, &consent(consent_row(db.ann, &db.portal, 1)))
            .await
            .unwrap();
        db.store.save(&db.tenant, &withdrawn).await.unwrap();

        let listed = db.store.list_for_user(&db.tenant, &db.ann).await.unwrap();

        let clients: Vec<&OAuthClientId> = listed.iter().map(OAuthConsent::client_id).collect();
        assert_eq!(clients, [reports.id(), db.portal.id()]);
        assert!(listed[0].scopes().is_empty());
    }

    /// Reading consent with an invalid stored scope returns an infrastructure
    /// error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_consent_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &consent(consent_row(db.ann, &db.portal, 1)))
            .await
            .unwrap();
        db.db
            .tamper("UPDATE oauth_consents SET scopes = ARRAY['not a scope']")
            .await;

        let read = db.store.find(&db.tenant, &db.ann, db.portal.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
