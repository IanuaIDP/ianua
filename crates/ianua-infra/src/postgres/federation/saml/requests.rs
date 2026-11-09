//! The SAML sign-in requests a tenant's connections sent and keep until
//! they are answered.
//!
//! A request is kept under its ID and removed as it is taken, so only an
//! answer to a request sent here is accepted, and only once. A request not
//! answered within [`LAPSE`] is never handed out, and the tenant's lapsed
//! ones are cleared when the next one is kept.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::{SamlLoginRequest, SamlRequestStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SamlRequestId;
use time::Duration;

use self::record::RequestRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long a request waits for the provider's answer before it lapses.
const LAPSE: Duration = Duration::minutes(10);

/// The Postgres store of SAML sign-in requests in flight.
pub struct PgSamlRequestStore {
    databases: Arc<Databases>,
}

impl PgSamlRequestStore {
    /// A store keeping requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSamlRequestStore {}

#[async_trait]
impl SamlRequestStore for PgSamlRequestStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request_id: &SamlRequestId,
        request: &SamlLoginRequest,
    ) -> Result<(), DomainError> {
        let now = clock::now();
        let lapses_at = now.saturating_add(LAPSE);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/saml_requests/clear_lapsed.sql",
                    tenant_id.as_uuid(),
                    now
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query_file!(
                    "queries/saml_requests/keep.sql",
                    tenant_id.as_uuid(),
                    request_id.as_str(),
                    request.connection_id.as_uuid(),
                    request.binding_hash.as_str(),
                    request.dashboard_hash.as_str(),
                    lapses_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        request_id: &SamlRequestId,
    ) -> Result<Option<SamlLoginRequest>, DomainError> {
        let now = clock::now();
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RequestRecord,
                    "queries/saml_requests/take.sql",
                    tenant_id.as_uuid(),
                    request_id.as_str(),
                    now
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        Ok(record.map(RequestRecord::into_request))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::federation::ConnectionStore;
    use ianua_domain::domains::federation::connection::FederatedIdpConnection;
    use ianua_domain::types::ConnectionId;

    use super::*;
    use crate::postgres::federation::PgConnectionStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::federation::{connection_row, saml_config, saml_login_request};

    struct Fixture {
        db: TestDb,
        store: PgSamlRequestStore,
        tenant: ScopedTenant,
        okta: ConnectionId,
    }

    /// A fresh database holding a tenant with Okta over SAML, and the store
    /// on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let okta =
            FederatedIdpConnection::reconstitute(connection_row("Okta", saml_config())).unwrap();
        PgConnectionStore::new(Arc::clone(&db.databases))
            .save(&tenant, &okta)
            .await
            .unwrap();
        Fixture {
            store: PgSamlRequestStore::new(Arc::clone(&db.databases)),
            okta: *okta.id(),
            tenant,
            db,
        }
    }

    fn request_id(text: &str) -> SamlRequestId {
        SamlRequestId::new(text).unwrap()
    }

    /// A request kept under its ID is handed out once, with the hashes its
    /// answer is checked against.
    #[tokio::test]
    async fn a_request_is_taken_once_under_its_id() {
        let fx = fixture().await;
        let kept = saml_login_request(fx.okta);
        let id = request_id("_a1b2c3d4e5f6");
        fx.store.save(&fx.tenant, &id, &kept).await.unwrap();

        let first = fx.store.take(&fx.tenant, &id).await.unwrap().unwrap();
        let again = fx.store.take(&fx.tenant, &id).await.unwrap();

        assert_eq!(first.connection_id, fx.okta);
        assert_eq!(first.binding_hash, kept.binding_hash);
        assert_eq!(first.dashboard_hash, kept.dashboard_hash);
        assert!(again.is_none());
    }

    /// Taking an unknown SAML request id returns none.
    #[tokio::test]
    async fn a_request_never_sent_takes_nothing() {
        let fx = fixture().await;

        let taken = fx
            .store
            .take(&fx.tenant, &request_id("_unsent"))
            .await
            .unwrap();

        assert!(taken.is_none());
    }

    /// A stored SAML request past its lapse time cannot be taken.
    #[tokio::test]
    async fn a_lapsed_request_is_not_taken() {
        let fx = fixture().await;
        let id = request_id("_lapsing");
        fx.store
            .save(&fx.tenant, &id, &saml_login_request(fx.okta))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE saml_requests SET lapses_at = now() - interval '1 minute'")
            .await;

        let taken = fx.store.take(&fx.tenant, &id).await.unwrap();

        assert!(taken.is_none());
    }

    /// Another tenant cannot take Acme's SAML request, and Acme can still
    /// take it afterwards.
    #[tokio::test]
    async fn another_tenants_request_is_not_taken() {
        let fx = fixture().await;
        let id = request_id("_acme1");
        fx.store
            .save(&fx.tenant, &id, &saml_login_request(fx.okta))
            .await
            .unwrap();

        let globex = fx.store.take(&tenant(), &id).await.unwrap();
        let acme = fx.store.take(&fx.tenant, &id).await.unwrap();

        assert!(globex.is_none());
        assert!(acme.is_some());
    }
}
